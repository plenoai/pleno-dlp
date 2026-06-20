// Elasticsearch connector. Scans document indices via the REST Search API.
//
// Surface: POST /<index>/_search?scroll=1m to open a scroll cursor, then
// POST /_search/scroll to drain it. Emits one chunk per document.
//
// Auth: API key (header), Basic (user/password), or Cloud-ID shorthand.
// Verify hits GET / (cluster info) to confirm connectivity and credentials.
//
// Pagination: scroll context — each response returns a _scroll_id used for
// the next page. The context is cleared when pagination finishes.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	esRequestTimeout = 60 * time.Second
	esScrollTTL      = "1m"
	esPageSize       = 100
)

func init() {
	Register("elasticsearch", Connector{
		SourceType:  sources.SourceElasticsearch,
		Scan:        scanElasticsearch,
		Verify:      verifyElasticsearch,
		Fingerprint: fingerprintElasticsearch,
	})
}

// scanElasticsearch opens a scroll cursor over one or more index patterns and
// emits every matching document as a chunk.
//
// cfg keys:
//   - host       (required) Elasticsearch host URL (e.g. https://es.example.com:9200)
//   - api_key    API key (base64-encoded id:key, mutually exclusive with user/password)
//   - user       Basic-auth username
//   - password   Basic-auth password
//   - index      index pattern (default "*", supports wildcards and comma-lists)
//   - query      Elasticsearch query JSON (default match_all)
func scanElasticsearch(ctx context.Context, cfg Config, emit Emit) error {
	previousState, err := loadSIEMIncrementalState(cfg[configKeyIncrementalPreviousState], "elasticsearch")
	if err != nil {
		return err
	}
	nextState := &siemIncrementalState{Version: 1, Events: map[string]siemEventIncrementalState{}}
	if previousState == nil {
		previousState = &siemIncrementalState{Version: 1, Events: map[string]siemEventIncrementalState{}}
	}
	state := &siemScanState{previous: previousState, next: nextState}
	defer func() {
		if data, err := json.Marshal(nextState); err == nil {
			cfg[configKeyIncrementalNextState] = string(data)
		}
	}()

	cli, err := newESClient(cfg)
	if err != nil {
		return err
	}

	index := cfg.Get("index", "*")
	queryJSON := cfg.Get("query", `{"match_all":{}}`)

	scrollID, firstHits, err := cli.openScroll(ctx, index, queryJSON)
	if err != nil {
		return fmt.Errorf("elasticsearch: open scroll: %w", err)
	}
	defer func() { _ = cli.clearScroll(ctx, scrollID) }()

	for hits := firstHits; len(hits) > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, hit := range hits {
			data, err := json.Marshal(hit.Source)
			if err != nil || len(data) == 0 {
				continue
			}
			ts := esDocTimestamp(hit.Source)
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider:  "elasticsearch",
					Host:      cli.host,
					Index:     hit.Index,
					EventID:   hit.ID,
					Timestamp: ts,
					Link:      fmt.Sprintf("%s/%s/_doc/%s", cli.host, hit.Index, hit.ID),
				},
			}
			key := "es:" + hit.Index + ":" + hit.ID
			if emitErr := emitSIEMIncremental(key, data, ts, state, meta, emit); emitErr != nil {
				if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
					return emitErr
				}
			}
		}
		nextHits, nextScrollID, err := cli.nextPage(ctx, scrollID)
		if err != nil {
			return fmt.Errorf("elasticsearch: scroll page: %w", err)
		}
		scrollID = nextScrollID
		hits = nextHits
	}
	return nil
}

func fingerprintElasticsearch(ctx context.Context, cfg Config) (string, error) {
	cli, err := newESClient(cfg)
	if err != nil {
		return "", err
	}
	index := cfg.Get("index", "*")
	queryJSON := cfg.Get("query", `{"match_all":{}}`)
	scrollID, firstHits, err := cli.openScroll(ctx, index, queryJSON)
	if err != nil {
		return "", fmt.Errorf("elasticsearch: open scroll for fingerprint: %w", err)
	}
	defer func() { _ = cli.clearScroll(ctx, scrollID) }()

	h := sha256.New()
	writeFingerprint(h, "elasticsearch-v1")
	writeFingerprint(h, cli.host)
	writeFingerprint(h, index)
	for hits := firstHits; len(hits) > 0; {
		for _, hit := range hits {
			data, _ := json.Marshal(hit.Source)
			ts := esDocTimestamp(hit.Source)
			writeSIEMFingerprintEvent(h, "es:"+hit.Index+":"+hit.ID, data, ts)
		}
		nextHits, nextID, err := cli.nextPage(ctx, scrollID)
		if err != nil {
			return "", err
		}
		scrollID = nextID
		hits = nextHits
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func verifyElasticsearch(ctx context.Context, cfg Config, secret string) (bool, error) {
	host := cfg["host"]
	if host == "" {
		return false, errors.New("elasticsearch: host is required for verification")
	}
	tmpCfg := Config{"host": strings.TrimRight(host, "/"), "api_key": secret}
	cli, err := newESClient(tmpCfg)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.host+"/", nil)
	if err != nil {
		return false, err
	}
	cli.addAuth(req)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type esClient struct {
	host     string
	apiKey   string
	user     string
	password string
	http     *http.Client
}

type esHit struct {
	Index  string         `json:"_index"`
	ID     string         `json:"_id"`
	Source map[string]any `json:"_source"`
}

func newESClient(cfg Config) (*esClient, error) {
	host := cfg["host"]
	if host == "" {
		return nil, errors.New("elasticsearch: host is required (set --host or ELASTICSEARCH_HOST)")
	}
	return &esClient{
		host:     strings.TrimRight(host, "/"),
		apiKey:   cfg["api_key"],
		user:     cfg["user"],
		password: cfg["password"],
		http:     &http.Client{Timeout: esRequestTimeout},
	}, nil
}

func (c *esClient) addAuth(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.apiKey)
	} else if c.user != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	req.Header.Set("Content-Type", "application/json")
}

func (c *esClient) openScroll(ctx context.Context, index, queryJSON string) (string, []esHit, error) {
	body := fmt.Sprintf(`{"size":%d,"query":%s}`, esPageSize, queryJSON)
	url := fmt.Sprintf("%s/%s/_search?scroll=%s", c.host, index, esScrollTTL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", nil, fmt.Errorf("elasticsearch: open scroll -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []esHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("elasticsearch: decode scroll response: %w", err)
	}
	return result.ScrollID, result.Hits.Hits, nil
}

func (c *esClient) nextPage(ctx context.Context, scrollID string) ([]esHit, string, error) {
	body := fmt.Sprintf(`{"scroll":"%s","scroll_id":"%s"}`, esScrollTTL, scrollID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/_search/scroll", strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("elasticsearch: scroll -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []esHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("elasticsearch: decode scroll page: %w", err)
	}
	return result.Hits.Hits, result.ScrollID, nil
}

func (c *esClient) clearScroll(ctx context.Context, scrollID string) error {
	body := fmt.Sprintf(`{"scroll_id":"%s"}`, scrollID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.host+"/_search/scroll", strings.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func esDocTimestamp(src map[string]any) string {
	for _, key := range []string{"@timestamp", "timestamp", "time", "date"} {
		if v, ok := src[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
