// Package zoho detects Zoho OAuth refresh tokens of the shape
// `1000.<base62>.<base62>` gated on the `zoho` keyword window. Refresh
// tokens grant long-lived access to the issuing scope but the OAuth
// endpoint is region-specific (accounts.zoho.com / .eu / .in / .com.au /
// .jp), so verification would require guessing the customer's data
// residency — surfaced as unverified-by-design.
package zoho

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b(1000\.[A-Za-z0-9]{32,}\.[A-Za-z0-9]{32,})\b`)

var contextKeywords = []string{"zoho", "zoho_refresh", "zoho_token", "zoho_oauth"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zoho }

func (Scanner) Keywords() []string { return []string{"zoho", "1000."} }

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
		out = append(out, detectors.Result{
			DetectorType: detectors.Zoho,
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
