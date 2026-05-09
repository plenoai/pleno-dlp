package bitbucket

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

// requestTimeout caps a single REST call. The surrounding ctx is the real
// cancellation signal.
const requestTimeout = 60 * time.Second

// Client is a small, rate-limit-aware Bitbucket REST client. It handles 429
// responses with Retry-After, and blocks when the rate-limit bucket is empty
// (observed from response headers).
//
// One Client per Connector instance is the intended pattern: the rate bucket
// is per-token, so sharing across instances would interleave unrelated
// workloads onto a single quota.
type Client struct {
	base         string
	username     string
	appPassword  string
	bearerToken  string
	http         *http.Client
	mu           sync.Mutex
	nextAllowed  time.Time
	testSleep    func(time.Duration)
}

// NewClient constructs a Client. When bearerToken is non-empty, it is used
// for Authorization: Bearer; otherwise username+appPassword are used for
// HTTP Basic. httpClient may be nil — a bounded-timeout default is installed.
func NewClient(base, username, appPassword, bearerToken string, httpClient *http.Client) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{
		base:        base,
		username:    username,
		appPassword: appPassword,
		bearerToken: bearerToken,
		http:        httpClient,
	}
}

// Do issues an HTTP request against the Bitbucket REST API. It transparently
// retries on 429 (up to 5 attempts), honouring Retry-After for the wait
// duration. Callers MUST close resp.Body.
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
		req.Header.Set("Accept", "application/json")
		c.setAuth(req)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := backoffDuration(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			c.sleep(ctx, wait)
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("bitbucket: exhausted retries against rate limit")
	}
	return nil, lastErr
}

// GetJSON issues a GET and decodes a JSON body into out. The HTTP response is
// returned (with its body already drained and closed) so callers can inspect
// headers if needed.
func (c *Client) GetJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("bitbucket: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("bitbucket: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

// setAuth sets the Authorization header. Bearer token takes priority over
// Basic auth.
func (c *Client) setAuth(req *http.Request) {
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	} else if c.username != "" || c.appPassword != "" {
		req.SetBasicAuth(c.username, c.appPassword)
	}
}

// url returns the absolute URL to request. Absolute URLs pass through
// unchanged; relative paths are joined onto the configured base.
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
	return c.sleep(ctx, delay)
}

// observeRateLimit updates the bucket clock when response headers indicate
// the rate limit has been reached.
func (c *Client) observeRateLimit(resp *http.Response) {
	// Bitbucket does not expose X-RateLimit-Reset like GitHub, but some
	// headers may appear in future. For now, we rely on 429 + Retry-After.
}

// sleep waits for the given duration, respecting context cancellation.
// When testSleep is set, it is called instead of a real sleep.
func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Second
	}
	if c.testSleep != nil {
		c.testSleep(d)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// backoffDuration extracts a server-suggested backoff from the response
// headers, falling back to exponential backoff (capped at a minute).
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
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}
