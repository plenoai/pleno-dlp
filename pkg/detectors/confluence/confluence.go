// Package confluence detects Atlassian Confluence API tokens (24-char base62)
// near a "confluence" keyword.
//
// Verify is unverified-by-design: like Jira, the Confluence Cloud API
// requires HTTP Basic with the account email and we don't parse the email
// out of the surrounding chunk. Surfacing unverified findings still helps
// operators rotate. Shape is identical to the legacy `atlassian` detector —
// we discriminate by the "confluence" keyword window so the operator sees
// which product the token belongs to.
package confluence

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)

var contextKeywords = []string{"confluence", "confluence_api", "confluence_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Confluence }

func (Scanner) Keywords() []string { return []string{"confluence"} }

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
		out = append(out, detectors.Result{
			DetectorType: detectors.Confluence,
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
