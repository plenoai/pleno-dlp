// Package adyen detects Adyen API keys (long alnum prefixed by AQE) gated on
// the `adyen` keyword window. Adyen API keys can be live or test scoped and
// the verification endpoint requires the merchant account name; we don't
// guess it from the chunk, so this surfaces unverified-by-design.
package adyen

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Adyen keys typically start with AQE (live) or AQF (test) and are long
// base64url-ish strings (64+ chars). Tighten on the AQ prefix to avoid
// generic base64 noise.
var tokenRe = regexp.MustCompile(`\b(AQE[A-Za-z0-9+/=]{40,200}|AQF[A-Za-z0-9+/=]{40,200})\b`)

var contextKeywords = []string{"adyen", "adyen_api_key", "adyen_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Adyen }

func (Scanner) Keywords() []string { return []string{"adyen"} }

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
			DetectorType: detectors.Adyen,
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
