// Package tailscale detects Tailscale auth keys (`tskey-auth-…`), API keys
// (`tskey-api-…`), OAuth client secrets (`tskey-client-…`), and verifies them
// against Tailscale's dedicated secret-scanning partner endpoint.
//
// Verify uses POST https://api.tailscale.com/api/v2/secret-scanning/verify with
// the raw token in the form field `key` (Content-Type
// application/x-www-form-urlencoded). This endpoint is purpose-built for
// scanners: it is non-destructive (it does NOT join a node to the tailnet the
// way `tailscale up` would), has a fixed host (no tailnet name or apiBase
// guessing required), and returns unambiguous codes — 204 = verified, 401 =
// not verified. The same endpoint validates tskey-auth, tskey-api, and
// tskey-oauth/tskey-client tokens uniformly. Everything other than 204/401 is
// surfaced as a VerificationError rather than a false verdict.
package tailscale

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.tailscale.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `tskey-` is the documented prefix; `auth-`, `api-`, `client-` are the
// sub-types. The body is base32/base62 of varying length and may contain
// underscores; mirror trufflehog's `tskey-[a-z]+-[0-9A-Za-z_]+-[0-9A-Za-z_]+`
// shape so verifiable OAuth/underscore tokens are not dropped.
var tokenRe = regexp.MustCompile(`\b(tskey-[a-z]+-[0-9A-Za-z_]{6,32}-[0-9A-Za-z_]{16,96})\b`)

var (
	verifyAcceptCodes = []int{http.StatusNoContent}
	verifyRejectCodes = []int{http.StatusUnauthorized}
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Tailscale }

func (Scanner) Keywords() []string { return []string{"tskey-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Tailscale,
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

// Verify checks the token against Tailscale's secret-scanning partner endpoint.
// The token itself is the credential — it is posted as form field `key` with
// no Authorization header. Honours a 5s timeout with a single retry on
// transport failure; 429/5xx are surfaced as transient errors (never
// Verified=true) per the repo error-handling policy.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, transportErr := doVerify(ctx, secret)
	if transportErr != nil {
		// Single retry on transport failure (not on an HTTP rejection).
		resp, transportErr = doVerify(ctx, secret)
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, transportErr, verifyAcceptCodes, verifyRejectCodes)
}

func doVerify(ctx context.Context, secret string) (*http.Response, error) {
	form := url.Values{}
	form.Set("key", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiBase+"/api/v2/secret-scanning/verify", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpClient.Do(req)
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
