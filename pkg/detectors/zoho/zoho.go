// Package zoho detects Zoho OAuth refresh tokens near Zoho context.
package zoho

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b1000\.([A-Za-z0-9]{32,})\.([A-Za-z0-9]{32,})\b`)

var contextKeywords = []string{"zoho", "zoho_refresh", "zoho_token", "zoho_oauth"}

const minSegmentEntropy = 3.5

var (
	allDecimalRe = regexp.MustCompile(`^[0-9]+$`)
	allHexRe     = regexp.MustCompile(`^[0-9a-f]+$`)
)

func plausibleSegment(seg string) bool {
	if allDecimalRe.MatchString(seg) || allHexRe.MatchString(seg) {
		return false
	}
	return detectors.HasMinEntropy(seg, minSegmentEntropy)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zoho }

func (Scanner) Keywords() []string { return []string{"zoho"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// h[0:2] full match, h[2:4] segment 1, h[4:6] segment 2.
		token := string(data[h[0]:h[1]])
		if _, dup := seen[token]; dup {
			continue
		}
		seg1 := string(data[h[2]:h[3]])
		seg2 := string(data[h[4]:h[5]])
		if !plausibleSegment(seg1) || !plausibleSegment(seg2) {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
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
	const radius = 64
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
