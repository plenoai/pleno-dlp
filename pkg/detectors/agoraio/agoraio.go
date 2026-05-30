// Package agoraio detects Agora.io realtime app ID + app certificate
// pairs near the `agora` keyword. Both halves are 32-hex strings.
// Unverified by design — Agora authenticates via offline-signed RTC
// tokens; there is no credential probe endpoint we can hit safely.
package agoraio

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var idRe = regexp.MustCompile(`\b([0-9a-f]{32})\b`)

var contextKeywords = []string{"agora"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AgoraIO }

func (Scanner) Keywords() []string { return []string{"agora"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := idRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	tokens := make([]string, 0, len(hits))
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		tokens = append(tokens, string(data[h[2]:h[3]]))
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i := 0; i < len(tokens); i++ {
		for j := 0; j < len(tokens); j++ {
			if i == j || tokens[i] == tokens[j] {
				continue
			}
			pair := tokens[i] + ":" + tokens[j]
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			out = append(out, detectors.Result{
				DetectorType: detectors.AgoraIO,
				Raw:          []byte(tokens[i]),
				RawV2:        []byte(pair),
				Redacted:     redact(tokens[i]),
			})
		}
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
