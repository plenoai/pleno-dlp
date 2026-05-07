// Package akamai detects Akamai EdgeGrid client_secret strings (32+ char
// base64) gated on the `akamai` keyword window. Akamai's EdgeGrid auth is
// an HMAC scheme (client_token + access_token + client_secret all required
// to sign each request), so a bare client_secret without the matching
// tokens cannot be verified against an upstream API — surfaced as
// unverified-by-design. Co-occurrence with the `akamai` keyword bounds
// the false-positive rate against generic 32-char base64 strings.
package akamai

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9+/=_\-]{32,})\b`)

var contextKeywords = []string{"akamai", "edgegrid", "akamai_client_secret", "akamai_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Akamai }

func (Scanner) Keywords() []string { return []string{"akamai"} }

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
		if len(token) < 32 || len(token) > 80 {
			continue
		}
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Akamai,
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
