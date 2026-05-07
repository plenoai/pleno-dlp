// Package spacelift detects Spacelift IaC platform API keys (`s_<base62>`)
// — distinct prefix; verification is not attempted because Spacelift uses
// per-account hosts (<account>.app.spacelift.io). Surfaced as unverified-by-
// design.
package spacelift

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is exposed for completeness — Spacelift uses per-account hosts
// (<account>.app.spacelift.io) so verify is unverified-by-design unless
// a co-occurring host is parsed.
var apiBase = "https://app.spacelift.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Spacelift API key/secret tokens are documented as `s_<32+ base62>`. The
// `s_` prefix is short — keyword gate adds safety.
var tokenRe = regexp.MustCompile(`\b(s_[A-Za-z0-9]{32,120})\b`)

var contextKeywords = []string{"spacelift", "spacelift_api"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Spacelift }

func (Scanner) Keywords() []string { return []string{"spacelift"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Spacelift,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Unverified by design: per-account host required.
		_ = verify
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

// Verify probes the user-overridable apiBase. Default host is generic; real
// deployments use <account>.app.spacelift.io and need an apiBase override.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/graphql", strings.NewReader(`{"query":"{ viewer { id } }"}`))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
