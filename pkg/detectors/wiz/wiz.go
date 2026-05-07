// Package wiz detects Wiz.io service-account / API tokens. Wiz uses long
// JWT-like base64url tokens (>=64 chars). Gated on the `wiz` keyword window
// so the broad shape doesn't collide with other JWT-looking tokens. Wiz
// Cloud requires a tenant-specific endpoint (api.<tenant>.app.wiz.io) so
// verification is left unimplemented — keyword + shape gating bound the
// false-positive rate.
package wiz

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_\-]{40,200}\.[A-Za-z0-9_\-]{40,200}\.[A-Za-z0-9_\-]{20,200})\b`)

var contextKeywords = []string{"wiz_io", "wiz.io", "wiz_token", "wiz_client_id", "wiz_client_secret", "auth.wiz.io"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Wiz }

func (Scanner) Keywords() []string { return []string{"wiz"} }

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
			DetectorType: detectors.Wiz,
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
