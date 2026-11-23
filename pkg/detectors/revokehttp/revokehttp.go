// Package revokehttp holds the small HTTP plumbing shared by detector
// Revoker implementations: a bounded request/response round trip, an
// env-or-override credential lookup, and a non-reversible ProviderID
// fingerprint. It performs no policy gating; the CLI owns that.
package revokehttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MaxBody caps how much of a provider response a Revoker inspects.
const MaxBody = 64 << 10

// Timeout bounds one Revoke round trip.
const Timeout = 10 * time.Second

// Response is a bounded snapshot of a provider reply.
type Response struct {
	Status int
	Body   []byte
}

// Do sends one request and returns the status plus at most MaxBody bytes.
// headers are applied verbatim; body may be nil.
func Do(ctx context.Context, c *http.Client, method, url string, headers map[string]string, body io.Reader) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return Response{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBody))
		_ = resp.Body.Close()
	}()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: resp.StatusCode, Body: b}, nil
}

// Env returns the trimmed value of name.
func Env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

// Fingerprint returns a stable non-reversible identifier for audit logs
// when the provider exposes no key id: the first 12 hex chars of SHA-256.
func Fingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(h[:6])
}

// StatusError formats a hard failure for an unexpected status.
func StatusError(provider string, status int) error {
	return fmt.Errorf("%s: revoke: unexpected HTTP %d", provider, status)
}
