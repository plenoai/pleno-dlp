package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAPIBase is the public github.com REST root. GitHub Enterprise
// callers override this via Config.APIBase / --api-base.
const DefaultAPIBase = "https://api.github.com"

// requestTimeout caps a single REST call. Tree and blob fetches against
// large monorepos can take a while, so the timeout is generous; the
// surrounding ctx is the real cancellation signal.
const requestTimeout = 60 * time.Second

// Client is a small, rate-limit-aware GitHub REST client. It parses the
// X-RateLimit-Remaining / X-RateLimit-Reset headers on every response so
// the next request blocks until the bucket refills, and it backs off on
// 429 / 403 secondary-rate-limit responses honouring Retry-After.
//
// One Client per Connector instance is the intended pattern: the rate
// bucket is per-token, so sharing across instances would interleave
// unrelated workloads onto a single quota.
type Client struct {
	base  string
	token string
	http  *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	// testSleep, when non-nil, is called instead of actually sleeping
	// during retry backoff. Tests wire this to assert "we would have
	// slept" without burning wall-clock time. Production code leaves
	// this nil so real sleeps happen on real rate limits.
	testSleep func(time.Duration)
}

// NewClient constructs a Client. httpClient may be nil — a bounded-timeout
// default is installed so a wedged GitHub doesn't pin the whole scan.
func NewClient(base, token string, httpClient *http.Client) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{base: base, token: token, http: httpClient}
}

// Do issues an HTTP request against the GitHub REST API. It transparently
// retries on 429 and on 403 secondary-rate-limit responses (up to 5
// attempts), honouring Retry-After and X-RateLimit-Reset for the wait
// duration. Callers MUST close resp.Body.
//
// path may be a relative path (joined onto Client.base) or an absolute
// URL — Link-header pagination hands us absolute URLs and we follow them
// verbatim.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			return nil, err
		}
		c.observeRateLimit(resp)
		if rateLimited(resp) {
			wait := backoffDuration(resp, attempt)
			// Drain and close so the connection is reusable.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
			}
			if wait <= 0 {
				wait = time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("github: exhausted retries against rate limit")
	}
	return nil, lastErr
}

// GetJSON issues a GET and decodes a JSON body into out. The HTTP
// response is returned (with its body already drained and closed) so
// callers can read the Link header for pagination.
func (c *Client) GetJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a bounded snippet of the error body for diagnostics.
		// GitHub returns JSON errors like {"message":"Not Found"}; a
		// few hundred bytes is plenty to identify the problem without
		// flooding logs.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("github: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("github: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

// url returns the absolute URL to request. Absolute paths (Link-header
// next pages) pass through unchanged; relative paths are joined onto the
// configured base.
func (c *Client) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

// waitForBucket blocks until the rate-limit bucket allows another call.
// When the previous response carried X-RateLimit-Remaining=0, we sleep
// until X-RateLimit-Reset; otherwise the call returns immediately.
func (c *Client) waitForBucket(ctx context.Context) error {
	c.mu.Lock()
	until := c.nextAllowed
	c.mu.Unlock()
	if until.IsZero() {
		return nil
	}
	delay := time.Until(until)
	if delay <= 0 {
		return nil
	}
	if c.testSleep != nil {
		c.testSleep(delay)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// observeRateLimit updates the bucket clock when GitHub tells us the
// current window is exhausted. Reset is a Unix epoch in seconds.
func (c *Client) observeRateLimit(resp *http.Response) {
	rem := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")
	if rem == "" || rem != "0" || reset == "" {
		return
	}
	ts, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.nextAllowed = time.Unix(ts, 0)
	c.mu.Unlock()
}

// rateLimited reports whether resp is a 429 or a 403 that carries the
// "Retry-After" / exhausted-bucket markers GitHub uses for secondary
// rate limiting (abuse detection).
func rateLimited(resp *http.Response) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode == http.StatusForbidden {
		if resp.Header.Get("Retry-After") != "" {
			return true
		}
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return true
		}
	}
	return false
}

// backoffDuration extracts a server-suggested backoff from the response
// headers, falling back to exponential backoff (capped at a minute) when
// the server didn't say.
func backoffDuration(resp *http.Response, attempt int) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(ts, 0)); d > 0 {
				return d
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}
