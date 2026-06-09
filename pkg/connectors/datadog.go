// Datadog connector. Scans Datadog Logs via the Log Search API.
//
// Surface: POST /api/v2/logs/events/search to page through stored logs.
// Each log event body is emitted as a chunk for detector scanning.
//
// Auth: DD-API-KEY + DD-APPLICATION-KEY headers.
// Verify hits GET /api/v1/validate to confirm API key validity.
//
// Pagination: cursor-based via data[].id + meta.page.after.

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
	datadogDefaultSite    = "https://api.datadoghq.com"
	datadogRequestTimeout = 60 * time.Second
	datadogPageLimit      = 100
)

func init() {
	Register("datadog", Connector{
		SourceType:  sources.SourceDatadog,
		Scan:        scanDatadog,
		Verify:      verifyDatadog,
		Fingerprint: fingerprintDatadog,
	})
}

// scanDatadog pages through Datadog Log Search results.
// cfg keys:
//   - api_key         (required) Datadog API key
//   - app_key         (required) Datadog Application key
//   - site            override https://api.datadoghq.com
//   - query           log search query (default "*")
//   - from            start time (RFC 3339, default 24h ago)
//   - to              end time   (RFC 3339, default now)
func scanDatadog(ctx context.Context, cfg Config, emit Emit) error {
	previousState, err := loadSIEMIncrementalState(cfg[configKeyIncrementalPreviousState], "datadog")
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

	apiKey := cfg["api_key"]
	if apiKey == "" {
		return errors.New("datadog: api_key is required (set --api-key or DD_API_KEY)")
	}
	appKey := cfg["app_key"]
	if appKey == "" {
		return errors.New("datadog: app_key is required (set --app-key or DD_APP_KEY)")
	}
	site := cfg.Get("site", datadogDefaultSite)
	query := cfg.Get("query", "*")

	from, to := datadogTimeRange(cfg)

	cli := &datadogClient{
		site:   strings.TrimRight(site, "/"),
		apiKey: apiKey,
		appKey: appKey,
		http:   &http.Client{Timeout: datadogRequestTimeout},
	}

	var cursor string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := cli.searchLogs(ctx, query, from, to, cursor)
		if err != nil {
			return fmt.Errorf("datadog: search logs: %w", err)
		}
		for _, evt := range resp.Data {
			msg := evt.Attributes.Message
			if msg == "" {
				continue
			}
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider:  "datadog",
					Host:      cli.site,
					Index:     evt.Attributes.Tags,
					EventID:   evt.ID,
					Timestamp: evt.Attributes.Timestamp,
					Link:      fmt.Sprintf("%s/logs?query=%s&event_id=%s", cli.site, query, evt.ID),
				},
			}
			if err := emitSIEMIncremental(datadogEventKey(evt), []byte(msg), evt.Attributes.Timestamp, state, meta, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		cursor = resp.Meta.Page.After
		if cursor == "" || len(resp.Data) == 0 {
			break
		}
	}
	return nil
}

func fingerprintDatadog(ctx context.Context, cfg Config) (string, error) {
	apiKey := cfg["api_key"]
	if apiKey == "" {
		return "", errors.New("datadog: api_key is required (set --api-key or DD_API_KEY)")
	}
	appKey := cfg["app_key"]
	if appKey == "" {
		return "", errors.New("datadog: app_key is required (set --app-key or DD_APP_KEY)")
	}
	site := cfg.Get("site", datadogDefaultSite)
	query := cfg.Get("query", "*")
	from, to := datadogTimeRange(cfg)
	cli := &datadogClient{
		site:   strings.TrimRight(site, "/"),
		apiKey: apiKey,
		appKey: appKey,
		http:   &http.Client{Timeout: datadogRequestTimeout},
	}
	h := sha256.New()
	writeFingerprint(h, "datadog-v1")
	writeFingerprint(h, cli.site)
	writeFingerprint(h, query)
	writeFingerprint(h, from)
	writeFingerprint(h, to)
	var cursor string
	for {
		resp, err := cli.searchLogs(ctx, query, from, to, cursor)
		if err != nil {
			return "", err
		}
		for _, evt := range resp.Data {
			if evt.Attributes.Message == "" {
				continue
			}
			writeSIEMFingerprintEvent(h, datadogEventKey(evt), []byte(evt.Attributes.Message), evt.Attributes.Timestamp)
		}
		cursor = resp.Meta.Page.After
		if cursor == "" || len(resp.Data) == 0 {
			break
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func datadogTimeRange(cfg Config) (string, string) {
	from := cfg["from"]
	to := cfg["to"]
	if from == "" {
		from = time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	}
	if to == "" {
		to = time.Now().UTC().Format(time.RFC3339)
	}
	return from, to
}

func datadogEventKey(evt datadogLogEvent) string {
	if evt.ID != "" {
		return evt.ID
	}
	return siemContentKey("datadog", []byte(evt.Attributes.Timestamp+"\x00"+evt.Attributes.Message))
}

func verifyDatadog(ctx context.Context, cfg Config, secret string) (bool, error) {
	site := cfg.Get("site", datadogDefaultSite)
	cli := &datadogClient{
		site:   strings.TrimRight(site, "/"),
		apiKey: secret,
		http:   &http.Client{Timeout: datadogRequestTimeout},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.site+"/api/v1/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("DD-API-KEY", secret)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type datadogClient struct {
	site   string
	apiKey string
	appKey string
	http   *http.Client
}

type datadogSearchResp struct {
	Data []datadogLogEvent `json:"data"`
	Meta struct {
		Page struct {
			After string `json:"after"`
		} `json:"page"`
	} `json:"meta"`
}

type datadogLogEvent struct {
	ID         string `json:"id"`
	Attributes struct {
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
		Tags      string `json:"tags"`
		Service   string `json:"service"`
	} `json:"attributes"`
}

func (c *datadogClient) searchLogs(ctx context.Context, query, from, to, cursor string) (*datadogSearchResp, error) {
	body := map[string]any{
		"filter": map[string]any{
			"query": query,
			"from":  from,
			"to":    to,
		},
		"page": map[string]any{
			"limit": datadogPageLimit,
		},
	}
	if cursor != "" {
		body["page"].(map[string]any)["cursor"] = cursor
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.site+"/api/v2/logs/events/search", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("datadog: POST logs/events/search -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result datadogSearchResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("datadog: decode search response: %w", err)
	}
	return &result, nil
}
