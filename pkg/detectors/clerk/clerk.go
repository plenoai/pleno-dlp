// Package clerk detects Clerk secret keys (`sk_test_…` / `sk_live_…` near
// a `clerk` keyword) and verifies them against /v1/users.
//
// Clerk's keys share the `sk_test_` / `sk_live_` prefix with Stripe. The
// disambiguator here is co-occurrence with a `clerk` keyword in the chunk;
// when both detectors fire on the same blob, downstream tooling deduplicates
// by Raw+location and the `Clerk` rule surfaces alongside the `Stripe` rule.
// Live keys grant production user-database admin access — surface them at
// SeverityCritical when shape and keyword both confirm.
package clerk

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.clerk.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b((?:sk_test_|sk_live_)[A-Za-z0-9]{32,})\b`)

var contextKeywords = []string{"clerk", "clerk_secret", "clerk_api", "clerk_dev", "clerk.com"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Clerk }

// We share the prefilter prefixes with Stripe — both detectors hit the
// same chunk, then the per-detector keyword gate sorts them out. Adding
// `clerk` as a prefilter keeps unambiguous chunks fast.
func (Scanner) Keywords() []string { return []string{"clerk"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Without a clerk keyword in the window we leave it to the Stripe
		// detector. This is the only thing distinguishing the two key
		// families in the wild.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		sev := detectors.SeverityHigh
		if strings.HasPrefix(token, "sk_live_") {
			sev = detectors.SeverityCritical
		}
		res := detectors.Result{
			DetectorType: detectors.Clerk,
			Raw:          []byte(token),
			Redacted:     redact(token),
			Severity:     sev,
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/users?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")

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

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	for _, p := range []string{"sk_test_", "sk_live_"} {
		if len(t) > len(p)+4 && t[:len(p)] == p {
			return t[:len(p)+4] + "..."
		}
	}
	if len(t) > 8 {
		return t[:8] + "..."
	}
	return t + "..."
}

func init() {
	detectors.Register(Scanner{})
}
