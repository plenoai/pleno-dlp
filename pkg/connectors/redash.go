// Redash connector. Scans Redash query results via the REST API.
//
// Surface: GET /api/queries to list queries, then
// GET /api/queries/{id}/results to retrieve the latest cached result
// for each query. Each row is serialized to JSON and emitted as a chunk.
//
// Auth: API key sent as query parameter (?api_key=...).
// Verify hits GET /api/session to confirm API key validity.
//
// Pagination: Redash caches full query results; rows are paged locally
// after fetching the JSON payload.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	redashRequestTimeout = 60 * time.Second
)

func init() {
	Register("redash", Connector{
		SourceType:  sources.SourceRedash,
		Scan:        scanRedash,
		Verify:      verifyRedash,
		Fingerprint: fingerprintRedash,
	})
}

// scanRedash lists queries and scans their cached results.
// cfg keys:
//   - api_key     (required) Redash API key
//   - host        (required) Redash host URL (e.g. https://redash.example.com)
//   - query_ids   comma-separated query IDs to scan (omit to scan all)
func scanRedash(ctx context.Context, cfg Config, emit Emit) error {
	previousState, err := loadSIEMIncrementalState(cfg[configKeyIncrementalPreviousState], "redash")
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
		return errors.New("redash: api_key is required (set --api-key or REDASH_API_KEY)")
	}
	host := cfg["host"]
	if host == "" {
		return errors.New("redash: host is required (set --host)")
	}
	host = strings.TrimRight(host, "/")

	cli := &redashClient{
		host:   host,
		apiKey: apiKey,
		http:   &http.Client{Timeout: redashRequestTimeout},
	}

	queryIDs, err := redashQueryIDs(ctx, cfg, cli)
	if err != nil {
		return err
	}

	for _, qid := range queryIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := cli.getQueryResult(ctx, qid)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			redashWarn("query %d: %v", qid, err)
			continue
		}
		for i, row := range result.Data.Rows {
			rowJSON, err := json.Marshal(row)
			if err != nil {
				continue
			}
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider:  "redash",
					Host:      host,
					Index:     result.QueryName,
					EventID:   fmt.Sprintf("q%d:r%d", qid, i),
					Timestamp: result.RetrievedAt,
					Link:      fmt.Sprintf("%s/queries/%d", host, qid),
				},
			}
			if err := emitSIEMIncremental(redashRowKey(qid, rowJSON), rowJSON, result.RetrievedAt, state, meta, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
	}
	return nil
}

func fingerprintRedash(ctx context.Context, cfg Config) (string, error) {
	apiKey := cfg["api_key"]
	if apiKey == "" {
		return "", errors.New("redash: api_key is required (set --api-key or REDASH_API_KEY)")
	}
	host := cfg["host"]
	if host == "" {
		return "", errors.New("redash: host is required (set --host)")
	}
	host = strings.TrimRight(host, "/")
	cli := &redashClient{
		host:   host,
		apiKey: apiKey,
		http:   &http.Client{Timeout: redashRequestTimeout},
	}
	queryIDs, err := redashQueryIDs(ctx, cfg, cli)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeFingerprint(h, "redash-v1")
	writeFingerprint(h, host)
	for _, qid := range queryIDs {
		result, err := cli.getQueryResult(ctx, qid)
		if err != nil {
			redashWarn("query %d: %v", qid, err)
			continue
		}
		if err := fingerprintRedashRows(h, qid, result); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func verifyRedash(ctx context.Context, cfg Config, secret string) (bool, error) {
	host := cfg["host"]
	if host == "" {
		return false, errors.New("redash: host is required for verification")
	}
	host = strings.TrimRight(host, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/api/session?api_key="+secret, nil)
	if err != nil {
		return false, err
	}
	cli := &http.Client{Timeout: redashRequestTimeout}
	resp, err := cli.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type redashClient struct {
	host   string
	apiKey string
	http   *http.Client
}

type redashQuery struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type redashQueryResult struct {
	QueryName   string `json:"-"`
	RetrievedAt string `json:"retrieved_at"`
	Data        struct {
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
		Rows []map[string]any `json:"rows"`
	} `json:"data"`
}

func redashQueryIDs(ctx context.Context, cfg Config, cli *redashClient) ([]int, error) {
	if ids := cfg["query_ids"]; ids != "" {
		var queryIDs []int
		for _, s := range strings.Split(ids, ",") {
			s = strings.TrimSpace(s)
			if id, err := strconv.Atoi(s); err == nil {
				queryIDs = append(queryIDs, id)
			}
		}
		return queryIDs, nil
	}
	listed, err := cli.listQueries(ctx)
	if err != nil {
		return nil, fmt.Errorf("redash: list queries: %w", err)
	}
	queryIDs := make([]int, len(listed))
	for i, q := range listed {
		queryIDs[i] = q.ID
	}
	return queryIDs, nil
}

func fingerprintRedashRows(h hash.Hash, qid int, result *redashQueryResult) error {
	writeFingerprint(h, strconv.Itoa(qid))
	writeFingerprint(h, result.QueryName)
	writeFingerprint(h, result.RetrievedAt)
	for _, row := range result.Data.Rows {
		rowJSON, err := json.Marshal(row)
		if err != nil {
			return err
		}
		writeSIEMFingerprintEvent(h, redashRowKey(qid, rowJSON), rowJSON, result.RetrievedAt)
	}
	return nil
}

func redashRowKey(qid int, rowJSON []byte) string {
	return fmt.Sprintf("q%d:%s", qid, siemContentKey("row", rowJSON))
}

func (c *redashClient) doGet(ctx context.Context, path string) (*http.Response, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path+sep+"api_key="+c.apiKey, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *redashClient) listQueries(ctx context.Context) ([]redashQuery, error) {
	var allQueries []redashQuery
	page := 1
	for {
		resp, err := c.doGet(ctx, fmt.Sprintf("/api/queries?page=%d&page_size=100", page))
		if err != nil {
			return nil, err
		}
		var result struct {
			Count   int           `json:"count"`
			Results []redashQuery `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("redash: decode query list: %w", err)
		}
		allQueries = append(allQueries, result.Results...)
		if len(allQueries) >= result.Count || len(result.Results) == 0 {
			break
		}
		page++
	}
	return allQueries, nil
}

func (c *redashClient) getQueryResult(ctx context.Context, queryID int) (*redashQueryResult, error) {
	resp, err := c.doGet(ctx, fmt.Sprintf("/api/queries/%d", queryID))
	if err != nil {
		return nil, err
	}
	var meta struct {
		Name           string `json:"name"`
		LatestResultID *int   `json:"latest_query_data_id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&meta)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("redash: decode query %d meta: %w", queryID, err)
	}
	if meta.LatestResultID == nil {
		return nil, fmt.Errorf("redash: query %d has no cached results", queryID)
	}

	resp2, err := c.doGet(ctx, fmt.Sprintf("/api/queries/%d/results", queryID))
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
		return nil, fmt.Errorf("redash: GET query/%d/results -> %s: %s", queryID, resp2.Status, strings.TrimSpace(string(b)))
	}
	var wrapper struct {
		QueryResult redashQueryResult `json:"query_result"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("redash: decode query %d results: %w", queryID, err)
	}
	wrapper.QueryResult.QueryName = meta.Name
	return &wrapper.QueryResult, nil
}

var redashWarn = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "redash: warning: "+format+"\n", args...)
}
