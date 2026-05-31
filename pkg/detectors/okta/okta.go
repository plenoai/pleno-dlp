// Package okta detects Okta API tokens (00... prefix + 40 URL-safe chars).
//
// The matched secret is an Okta SSWS API token, which Okta accepts via the
// `Authorization: SSWS <token>` header against `GET /api/v1/users/me`
// (200 = valid, 401/403 = invalid — the trufflehog convention). The token
// is opaque and carries NO tenant information, and we do not extract the
// tenant (`<tenant>.okta.com` / `.oktapreview.com`) from the surrounding
// context reliably enough to probe it without risk of hitting the wrong
// tenant. Verify therefore only fires when an apiBase override supplies the
// tenant host explicitly; without it the leak is still surfaced unverified
// and operators should rotate immediately on any hit. This matches the
// apiBase-override pattern used by jumio / grafana and is class (a) per repo
// policy.
package okta

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase, when set (operator override), is the tenant host to verify against,
// e.g. "https://example.okta.com". Empty => Verify no-ops (unverified-by-design).
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Okta tokens start with "00" then 40 URL-safe base64-ish chars (alphanum,
// underscore, hyphen). The shape is documented and stable.
var tokenRe = regexp.MustCompile(`\b(00[A-Za-z0-9_-]{40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Okta }

// "00" alone would prefilter every chunk that contains the digit pair (i.e.
// almost everything), so we anchor on "okta" instead. Operators who paste
// just the token into a config without the keyword will be missed — that's
// an acceptable trade for a usable prefilter.
func (Scanner) Keywords() []string { return []string{"okta"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Okta,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Verify only fires with an apiBase override (tenant host is not
		// derivable from the token). Without it, Verified stays false.
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

// Verify confirms an Okta SSWS API token against the operator-supplied tenant
// host (apiBase). It no-ops (Verified=false, nil) when apiBase is unset,
// because the tenant is not recoverable from the token alone.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(apiBase, "/")+"/api/v1/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "SSWS "+secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pleno-dlp/okta")
	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// 200 => valid; 401/403 => invalid; 429/5xx => transient (surface error so
	// the engine marks "verification failed" rather than "not valid"); anything
	// else => treated as rejection. Never asserts Verified=true ambiguously.
	return detectors.ClassifyVerifyHTTP(resp, err, []int{http.StatusOK},
		[]int{http.StatusUnauthorized, http.StatusForbidden})
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
