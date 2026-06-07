// BigQuery connector. Scans BigQuery tables/views via the REST API.
//
// Surface: POST /bigquery/v2/projects/{project}/queries to run a query,
// then GET /bigquery/v2/projects/{project}/queries/{jobId} to page
// through results. Each row is serialized to JSON and emitted as a chunk.
//
// Auth: OAuth2 Bearer token (service account or user credential).
// Verify hits GET /bigquery/v2/projects/{project}/datasets to confirm
// read access.
//
// Pagination: pageToken-based via query results endpoint.

package connectors

import (
	"context"
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
	bigqueryAPIBase        = "https://bigquery.googleapis.com"
	bigqueryRequestTimeout = 120 * time.Second
	bigqueryMaxRows        = 500
)

func init() {
	Register("bigquery", Connector{
		SourceType: sources.SourceBigQuery,
		Scan:       scanBigQuery,
		Verify:     verifyBigQuery,
	})
}

// scanBigQuery runs a SQL query against BigQuery and emits each result row.
// cfg keys:
//   - token       (required) OAuth2 Bearer token
//   - project     (required) GCP project ID
//   - query       (required) SQL query to execute
//   - api_base    override https://bigquery.googleapis.com
func scanBigQuery(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("bigquery: token is required (set --token or BIGQUERY_TOKEN)")
	}
	project := cfg["project"]
	if project == "" {
		return errors.New("bigquery: project is required (set --project)")
	}
	query := cfg["query"]
	if query == "" {
		return errors.New("bigquery: query is required (set --query)")
	}
	apiBase := cfg.Get("api_base", bigqueryAPIBase)
	apiBase = strings.TrimRight(apiBase, "/")

	cli := &bigqueryClient{
		apiBase: apiBase,
		token:   token,
		project: project,
		http:    &http.Client{Timeout: bigqueryRequestTimeout},
	}

	resp, err := cli.runQuery(ctx, query)
	if err != nil {
		return fmt.Errorf("bigquery: run query: %w", err)
	}

	if err := emitBigQueryRows(ctx, cli, resp, query, emit); err != nil {
		return err
	}

	pageToken := resp.PageToken
	for pageToken != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := cli.getQueryResults(ctx, resp.JobReference.JobID, pageToken)
		if err != nil {
			return fmt.Errorf("bigquery: get query results: %w", err)
		}
		if err := emitBigQueryRows(ctx, cli, page, query, emit); err != nil {
			return err
		}
		pageToken = page.PageToken
	}
	return nil
}

func emitBigQueryRows(ctx context.Context, cli *bigqueryClient, resp *bigqueryQueryResp, query string, emit Emit) error {
	fields := make([]string, len(resp.Schema.Fields))
	for i, f := range resp.Schema.Fields {
		fields[i] = f.Name
	}
	for i, row := range resp.Rows {
		record := make(map[string]string, len(fields))
		for j, cell := range row.F {
			if j < len(fields) {
				record[fields[j]] = cell.V
			}
		}
		rowJSON, err := json.Marshal(record)
		if err != nil {
			continue
		}
		meta := sources.Metadata{
			SIEM: &sources.SIEMMeta{
				Provider:  "bigquery",
				Host:      cli.project,
				Index:     query,
				EventID:   fmt.Sprintf("%s:%d", resp.JobReference.JobID, i),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Link:      fmt.Sprintf("https://console.cloud.google.com/bigquery?project=%s&j=bq:%s:%s", cli.project, cli.project, resp.JobReference.JobID),
			},
		}
		if err := emit(rowJSON, meta); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

func verifyBigQuery(ctx context.Context, cfg Config, secret string) (bool, error) {
	project := cfg["project"]
	if project == "" {
		return false, errors.New("bigquery: project is required for verification")
	}
	apiBase := cfg.Get("api_base", bigqueryAPIBase)
	apiBase = strings.TrimRight(apiBase, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/bigquery/v2/projects/%s/datasets?maxResults=1", apiBase, project), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	cli := &http.Client{Timeout: bigqueryRequestTimeout}
	resp, err := cli.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type bigqueryClient struct {
	apiBase string
	token   string
	project string
	http    *http.Client
}

type bigqueryQueryResp struct {
	JobReference struct {
		JobID string `json:"jobId"`
	} `json:"jobReference"`
	Schema struct {
		Fields []struct {
			Name string `json:"name"`
		} `json:"fields"`
	} `json:"schema"`
	Rows []struct {
		F []struct {
			V string `json:"v"`
		} `json:"f"`
	} `json:"rows"`
	PageToken   string `json:"pageToken"`
	JobComplete bool   `json:"jobComplete"`
	TotalRows   string `json:"totalRows"`
}

func (c *bigqueryClient) doReq(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *bigqueryClient) runQuery(ctx context.Context, query string) (*bigqueryQueryResp, error) {
	payload, err := json.Marshal(map[string]any{
		"query":        query,
		"useLegacySql": false,
		"maxResults":   bigqueryMaxRows,
	})
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/bigquery/v2/projects/%s/queries", c.project)
	resp, err := c.doReq(ctx, http.MethodPost, path, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("bigquery: POST queries -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result bigqueryQueryResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("bigquery: decode query response: %w", err)
	}
	if !result.JobComplete {
		return c.waitAndGetResults(ctx, result.JobReference.JobID)
	}
	return &result, nil
}

func (c *bigqueryClient) waitAndGetResults(ctx context.Context, jobID string) (*bigqueryQueryResp, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := c.getQueryResults(ctx, jobID, "")
		if err != nil {
			return nil, err
		}
		if resp.JobComplete {
			return resp, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *bigqueryClient) getQueryResults(ctx context.Context, jobID, pageToken string) (*bigqueryQueryResp, error) {
	path := fmt.Sprintf("/bigquery/v2/projects/%s/queries/%s?maxResults=%d", c.project, jobID, bigqueryMaxRows)
	if pageToken != "" {
		path += "&pageToken=" + pageToken
	}
	resp, err := c.doReq(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("bigquery: GET query results -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result bigqueryQueryResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("bigquery: decode query results: %w", err)
	}
	return &result, nil
}
