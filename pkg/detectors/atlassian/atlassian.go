// Package atlassian detects Atlassian Cloud API tokens (24-char base62).
//
// Verify is intentionally not implemented. The /me endpoint requires Basic
// auth with the user's email as the username, and we don't extract the
// email from the surrounding chunk reliably. Surfacing unverified findings
// is still valuable — the operator can rotate the token without us
// confirming it's live.
package atlassian

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 24 base62 characters (no special chars). This shape collides with many
// commit-sha-ish strings, so the keyword gate is mandatory.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)

var contextKeywords = []string{"atlassian", "atlassian_api"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Atlassian }

// "atlassian" alone — the hardcoded "ATLASSIAN_API" envvar pattern is
// already covered case-insensitively.
func (Scanner) Keywords() []string { return []string{"atlassian"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		// Verified=false by design — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Atlassian,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
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
