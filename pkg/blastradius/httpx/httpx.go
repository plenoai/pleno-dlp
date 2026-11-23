// Package httpx holds the small HTTP helpers shared by blast-radius mappers.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxBody bounds every provider response body read by a mapper.
const MaxBody = 4 << 20

// DefaultClient is used when a mapper's Client is nil.
var DefaultClient = &http.Client{Timeout: 20 * time.Second}

// Client returns c or DefaultClient.
func Client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return DefaultClient
}

// GetJSON performs a GET with the given headers and decodes a 2xx JSON body
// into dst. It returns the response headers for scope extraction.
func GetJSON(ctx context.Context, c *http.Client, url string, hdr map[string]string, dst any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	return Do(Client(c), req, dst)
}

// Do sends req and decodes a 2xx JSON body into dst (nil dst discards it).
func Do(c *http.Client, req *http.Request, dst any) (http.Header, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, &StatusError{Code: resp.StatusCode, URL: req.URL.Path}
	}
	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return resp.Header, fmt.Errorf("decode %s: %w", req.URL.Path, err)
		}
	}
	return resp.Header, nil
}

// StatusError reports a non-2xx provider response. The body is never
// included because it may echo credential material.
type StatusError struct {
	Code int
	URL  string
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Code) }
