// Package freshdesk detects Freshdesk API keys (alphanumeric, ~20 chars,
// near `freshdesk` keyword).
//
// Verify is intentionally not performed. Freshdesk's API endpoint host is
// tenant-scoped (`<subdomain>.freshdesk.com`) and the subdomain is rarely
// embedded next to the token in source. Probing a guessed host risks
// wrong-account audit-log entries. So freshdesk surfaces unverified-by-
// design and the engine renders it under --unverified-results.
package freshdesk

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Freshdesk API keys are documented as 20-char base62. We accept 20..40 to
// allow for any future key-length bumps without dropping coverage.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,40})\b`)

// Optional subdomain capture for ExtraData.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.freshdesk\.com)\b`)

var contextKeywords = []string{"freshdesk", "freshworks"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Freshdesk }

func (Scanner) Keywords() []string { return []string{"freshdesk", "freshworks"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	host := hostRe.FindString(string(data))
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// 20+ alnum is far too generic without a Freshdesk co-occurrence
		// keyword in the same 256-byte window.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = strings.ToLower(host)
		}
		res := detectors.Result{
			DetectorType: detectors.Freshdesk,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
