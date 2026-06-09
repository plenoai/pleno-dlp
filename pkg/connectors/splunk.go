// Splunk connector. Scans Splunk Enterprise/Cloud via the REST search API.
//
// Surface: POST /services/search/jobs to dispatch a search, then
// GET /services/search/jobs/{sid}/results to retrieve results.
//
// Auth: Splunk token (Bearer) or session key.
// Verify hits GET /services/authentication/current-context.
//
// Pagination: offset + count based via results endpoint.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	splunkRequestTimeout = 120 * time.Second
	splunkPollInterval   = 2 * time.Second
	splunkPageCount      = 100
)

func init() {
	Register("splunk", Connector{
		SourceType:  sources.SourceSplunk,
		Scan:        scanSplunk,
		Verify:      verifySplunk,
		Fingerprint: fingerprintSplunk,
	})
}

// scanSplunk dispatches a search job and pages through the results.
// cfg keys:
//   - token       (required) Splunk Bearer token or session key
//   - host        (required) Splunk host URL (e.g. https://splunk.example.com:8089)
//   - query       SPL search query (default "search index=* | head 1000")
//   - earliest    earliest time (default "-24h")
//   - latest      latest time (default "now")
func scanSplunk(ctx context.Context, cfg Config, emit Emit) error {
	previousState, err := loadSIEMIncrementalState(cfg[configKeyIncrementalPreviousState], "splunk")
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

	token := cfg["token"]
	if token == "" {
		return errors.New("splunk: token is required (set --token or SPLUNK_TOKEN)")
	}
	host := cfg["host"]
	if host == "" {
		return errors.New("splunk: host is required (set --host)")
	}
	host = strings.TrimRight(host, "/")
	query := cfg.Get("query", "search index=* | head 1000")
	earliest := cfg.Get("earliest", "-24h")
	latest := cfg.Get("latest", "now")

	cli := &splunkClient{
		host:  host,
		token: token,
		http:  &http.Client{Timeout: splunkRequestTimeout},
	}

	sid, err := cli.createJob(ctx, query, earliest, latest)
	if err != nil {
		return fmt.Errorf("splunk: create search job: %w", err)
	}

	if err := cli.waitForJob(ctx, sid); err != nil {
		return fmt.Errorf("splunk: wait for search job %s: %w", sid, err)
	}

	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		results, err := cli.getResults(ctx, sid, offset, splunkPageCount)
		if err != nil {
			return fmt.Errorf("splunk: get results: %w", err)
		}
		if len(results) == 0 {
			break
		}
		for _, r := range results {
			raw := r.Raw
			if raw == "" {
				continue
			}
			meta := sources.Metadata{
				SIEM: &sources.SIEMMeta{
					Provider:  "splunk",
					Host:      host,
					Index:     r.Index,
					EventID:   r.CD,
					Timestamp: r.Time,
					Link:      fmt.Sprintf("%s/app/search/search?q=%s&sid=%s", host, url.QueryEscape(query), sid),
				},
			}
			if err := emitSIEMIncremental(splunkEventKey(r), []byte(raw), r.Time, state, meta, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		offset += len(results)
		if len(results) < splunkPageCount {
			break
		}
	}
	return nil
}

func fingerprintSplunk(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", errors.New("splunk: token is required (set --token or SPLUNK_TOKEN)")
	}
	host := cfg["host"]
	if host == "" {
		return "", errors.New("splunk: host is required (set --host)")
	}
	host = strings.TrimRight(host, "/")
	query := cfg.Get("query", "search index=* | head 1000")
	earliest := cfg.Get("earliest", "-24h")
	latest := cfg.Get("latest", "now")
	cli := &splunkClient{
		host:  host,
		token: token,
		http:  &http.Client{Timeout: splunkRequestTimeout},
	}
	sid, err := cli.createJob(ctx, query, earliest, latest)
	if err != nil {
		return "", fmt.Errorf("splunk: create search job: %w", err)
	}
	if err := cli.waitForJob(ctx, sid); err != nil {
		return "", fmt.Errorf("splunk: wait for search job %s: %w", sid, err)
	}
	h := sha256.New()
	writeFingerprint(h, "splunk-v1")
	writeFingerprint(h, host)
	writeFingerprint(h, query)
	writeFingerprint(h, earliest)
	writeFingerprint(h, latest)
	offset := 0
	for {
		results, err := cli.getResults(ctx, sid, offset, splunkPageCount)
		if err != nil {
			return "", err
		}
		if len(results) == 0 {
			break
		}
		for _, r := range results {
			if r.Raw == "" {
				continue
			}
			writeSIEMFingerprintEvent(h, splunkEventKey(r), []byte(r.Raw), r.Time)
		}
		offset += len(results)
		if len(results) < splunkPageCount {
			break
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func splunkEventKey(r splunkResult) string {
	if r.CD != "" {
		return r.CD
	}
	return siemContentKey("splunk", []byte(r.Time+"\x00"+r.Raw))
}

func verifySplunk(ctx context.Context, cfg Config, secret string) (bool, error) {
	host := cfg["host"]
	if host == "" {
		return false, errors.New("splunk: host is required for verification")
	}
	host = strings.TrimRight(host, "/")
	cli := &splunkClient{
		host:  host,
		token: secret,
		http:  &http.Client{Timeout: splunkRequestTimeout},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/services/authentication/current-context?output_mode=json", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type splunkClient struct {
	host  string
	token string
	http  *http.Client
}

type splunkResult struct {
	Raw   string `json:"_raw"`
	Time  string `json:"_time"`
	Index string `json:"_indextime,omitempty"`
	CD    string `json:"_cd"`
}

func (c *splunkClient) doReq(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.host+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(req)
}

func (c *splunkClient) createJob(ctx context.Context, query, earliest, latest string) (string, error) {
	form := url.Values{}
	form.Set("search", query)
	form.Set("earliest_time", earliest)
	form.Set("latest_time", latest)
	form.Set("output_mode", "json")

	resp, err := c.doReq(ctx, http.MethodPost, "/services/search/jobs", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("splunk: POST search/jobs -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		SID string `json:"sid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("splunk: decode create job response: %w", err)
	}
	return result.SID, nil
}

func (c *splunkClient) waitForJob(ctx context.Context, sid string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := c.doReq(ctx, http.MethodGet, "/services/search/jobs/"+sid+"?output_mode=json", nil, "")
		if err != nil {
			return err
		}
		var status struct {
			Entry []struct {
				Content struct {
					IsDone bool `json:"isDone"`
				} `json:"content"`
			} `json:"entry"`
		}
		err = json.NewDecoder(resp.Body).Decode(&status)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("splunk: decode job status: %w", err)
		}
		if len(status.Entry) > 0 && status.Entry[0].Content.IsDone {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(splunkPollInterval):
		}
	}
}

func (c *splunkClient) getResults(ctx context.Context, sid string, offset, count int) ([]splunkResult, error) {
	path := fmt.Sprintf("/services/search/jobs/%s/results?output_mode=json&offset=%d&count=%d", sid, offset, count)
	resp, err := c.doReq(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("splunk: GET results -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Results []splunkResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("splunk: decode results: %w", err)
	}
	return result.Results, nil
}
