// Package jira detects Atlassian Jira API tokens (24-char base62) near a
// "jira" / "atlassian" keyword.
//
// Verify is unverified-by-design: the /rest/api/3/myself endpoint requires
// HTTP Basic with the user's email as the username, and we do not parse the
// account email out of the surrounding chunk. Surfacing unverified findings
// is still valuable — operators rotate the token without confirming it's
// live. The shape is identical to the legacy `Atlassian` detector but the
// keyword gate ("jira") narrows the surface so we don't double-fire on every
// generic atlassian token. We keep both because trufflehog's parity does.
package jira

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 24 base62 characters. Same shape as `atlassian` — we differentiate by the
// "jira" keyword window, not by token format.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)

var contextKeywords = []string{"jira", "jira_api", "jira_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jira }

func (Scanner) Keywords() []string { return []string{"jira"} }

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
			DetectorType: detectors.Jira,
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
