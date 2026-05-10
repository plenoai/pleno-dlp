// Package stripe detects Stripe live/test secret keys (sk_live_, sk_test_,
// rk_live_) and verifies them via the /v1/charges list endpoint.
//
// Revoke (issue #73) only supports Stripe restricted keys (rk_test_ /
// rk_live_) via POST /v1/api_keys/{key}/revoke with the key acting as
// its own bearer (self-revoke). The standard sk_live_ / sk_test_ secret
// keys do NOT expose a programmatic revoke endpoint — they must be
// rotated via the Stripe dashboard. Revoke surfaces sk_-prefixed input
// as an explicit unsupported error so callers don't silently believe
// the secret is dead. HTTP 404 against the self-revoke path is treated
// as idempotent (already revoked / never existed).
package stripe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.stripe.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sk_live_, sk_test_, rk_live_ all share the same suffix shape: 20–247 base62
// chars. trufflehog uses the same canonical pattern.
var keyRe = regexp.MustCompile(`\b((?:sk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,247})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Stripe }

func (Scanner) Keywords() []string { return []string{"sk_live_", "sk_test_", "rk_live_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.Stripe,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/charges", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

// redact preserves the recognizable provider prefix plus four chars so
// operators can correlate findings without seeing the live secret.
func redact(t string) string {
	for _, p := range []string{"sk_live_", "sk_test_", "rk_live_"} {
		if len(t) > len(p)+4 && t[:len(p)] == p {
			return t[:len(p)+4] + "..."
		}
	}
	if len(t) > 8 {
		return t[:8] + "..."
	}
	return t + "..."
}

// Revoke implements detectors.Revoker for Stripe restricted keys.
//
// Stripe exposes self-revocation only for restricted keys (rk_test_ /
// rk_live_) via POST /v1/api_keys/{key}/revoke. The key authenticates
// the request as its own Bearer token and identifies itself in the
// path. Standard secret keys (sk_live_ / sk_test_) have no programmatic
// revoke surface — those rotate via the dashboard, so we reject them
// with an explicit error rather than pretending the call could succeed.
//
// Status handling:
//   - 200 + {"revoked": true}  -> Revoked = true.
//   - 200 + {"revoked": false} -> Revoked = false; non-fatal err carries
//     the response snippet so the caller can log why Stripe declined.
//   - 404 Not Found            -> idempotent: token already revoked or
//     never existed. Revoked = true with a non-fatal note.
//   - 401 Unauthorized         -> hard error (key invalid).
//   - 429 Too Many Requests    -> hard error; we do not retry, matching
//     the Verify policy so a rate-limited provider can't stall a scan.
//   - other 4xx / 5xx          -> hard error with status + body snippet.
//
// ProviderID echoes the key's prefix-bounded id (the segment after
// `rk_(test|live)_`) so audit logs can cross-reference revocations
// without recording the full secret.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("stripe: revoke: empty secret")
	}
	if !strings.HasPrefix(secret, "rk_test_") && !strings.HasPrefix(secret, "rk_live_") {
		return detectors.RevokeResult{}, errors.New("stripe: revoke: only restricted keys (rk_test_/rk_live_) are supported; sk_ secret keys must be rotated via the dashboard")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := apiBase + "/v1/api_keys/" + secret + "/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	now := time.Now().UTC()
	providerID := stripeProviderID(secret)

	switch resp.StatusCode {
	case http.StatusOK:
		// Read a bounded snippet so we can cheaply detect {"revoked": false}
		// without pulling in encoding/json — the API contract is stable
		// enough that a substring check is sufficient and keeps the
		// dependency surface minimal.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s := string(body)
		if strings.Contains(s, "\"revoked\":false") || strings.Contains(s, "\"revoked\": false") {
			return detectors.RevokeResult{Revoked: false, ProviderID: providerID, Err: fmt.Errorf("stripe: revoke: provider returned revoked=false: %s", s)}, nil
		}
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID}, nil
	case http.StatusNotFound:
		// Idempotent: key already revoked or never existed.
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID, Err: errors.New("stripe: revoke: already revoked or never existed (HTTP 404)")}, nil
	case http.StatusUnauthorized:
		return detectors.RevokeResult{}, errors.New("stripe: revoke: unauthorized (HTTP 401) — key invalid or already revoked at the auth layer")
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("stripe: revoke: rate-limited (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("stripe: revoke: unexpected status %s: %s", resp.Status, string(snippet))
	}
}

// stripeProviderID extracts the key's identifier segment so audit logs
// can correlate without storing the full secret. For `rk_test_xyz` we
// return `rk_test_xyz` truncated to a prefix-bounded form — Stripe does
// not expose a separate stable id for restricted keys outside the key
// itself, so we return the key's recognisable prefix and short tail.
func stripeProviderID(secret string) string {
	for _, p := range []string{"rk_live_", "rk_test_"} {
		if strings.HasPrefix(secret, p) {
			tailStart := len(p)
			tailEnd := tailStart + 4
			if tailEnd > len(secret) {
				tailEnd = len(secret)
			}
			return p + secret[tailStart:tailEnd]
		}
	}
	return ""
}

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
