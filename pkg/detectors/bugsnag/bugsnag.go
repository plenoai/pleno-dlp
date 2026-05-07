// Package bugsnag detects Bugsnag API keys (32 hex near the `bugsnag`
// keyword).
//
// Verify is intentionally not implemented. Bugsnag's documented endpoints
// (`/projects`, `/organizations`) authenticate with a personal auth token
// (`token <token>`), not the per-project API key the code-side keyword
// decorates. The API key alone gates `/notify` (event ingest), but probing
// /notify would inject synthetic events into the owner's project — a
// destructive side effect we will not perform during a scan. So bugsnag
// surfaces unverified-by-design.
package bugsnag

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 32-hex (lowercase) is the documented API key shape.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"bugsnag", "bugsnag_api_key", "bugsnag_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bugsnag }

func (Scanner) Keywords() []string { return []string{"bugsnag"} }

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
			DetectorType: detectors.Bugsnag,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
