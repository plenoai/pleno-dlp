// Package stytch detects Stytch project secrets (secret-test-/secret-live-)
// gated on the `stytch` keyword window. Stytch uses HTTP Basic auth with
// the project_id as the username and the secret as the password — the
// project_id (project-test-<uuid> / project-live-<uuid>) is required for
// any API call. We surface the secret unverified-by-design and let the
// operator rotate. secret-live- pairs surface SeverityCritical.
package stytch

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b(secret-(?:test|live)-[A-Za-z0-9_=\-]{32,})\b`)

var contextKeywords = []string{"stytch", "stytch_secret", "stytch_project"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Stytch }

func (Scanner) Keywords() []string { return []string{"stytch", "secret-test-", "secret-live-"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
			DetectorType: detectors.Stytch,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if strings.HasPrefix(token, "secret-live-") {
			res.Severity = detectors.SeverityCritical
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
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
