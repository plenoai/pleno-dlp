// Package httpx holds the small HTTP helpers shared by blast-radius mappers.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// NextLink extracts the rel="next" target from an RFC 8288 Link header.
func NextLink(h http.Header) string {
	for _, part := range strings.Split(h.Get("Link"), ",") {
		seg := strings.Split(part, ";")
		if len(seg) < 2 {
			continue
		}
		for _, p := range seg[1:] {
			if strings.ReplaceAll(strings.TrimSpace(p), " ", "") == `rel="next"` {
				return strings.Trim(strings.TrimSpace(seg[0]), "<>")
			}
		}
	}
	return ""
}

// SameOrigin reports whether next shares scheme and host with base, so a
// provider-supplied pagination link never redirects credentials elsewhere.
func SameOrigin(base, next string) bool {
	b, err1 := url.Parse(base)
	n, err2 := url.Parse(next)
	return err1 == nil && err2 == nil && b.Scheme == n.Scheme && strings.EqualFold(b.Host, n.Host)
}

// GetLinkPages follows Link rel="next" pagination from first, decoding each
// page's JSON array into items until maxItems is reached. truncated reports
// that more items exist beyond the cap.
func GetLinkPages[T any](ctx context.Context, c *http.Client, first string, hdr map[string]string, maxItems int) (items []T, truncated bool, err error) {
	next := first
	for next != "" {
		var page []T
		h, err := GetJSON(ctx, c, next, hdr, &page)
		if err != nil {
			return items, false, err
		}
		items = append(items, page...)
		n := NextLink(h)
		if len(items) >= maxItems {
			return items[:maxItems], n != "" || len(items) > maxItems, nil
		}
		if n != "" && !SameOrigin(first, n) {
			return items, true, nil
		}
		next = n
	}
	return items, false, nil
}
