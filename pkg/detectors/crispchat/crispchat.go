// Package crispchat detects Crisp Chat (crisp.chat) plugin tokens — long
// base64url tokens near `crisp` keyword. Crisp uses an Identifier+Key pair
// for plugin authentication; we surface the secret-key as Raw because the
// Identifier is a UUID and not by itself sensitive. Verified via /v1/user/account
// on api.crisp.chat using HTTP Basic with `Identifier:Key` — but since the
// detector ships only the Key, this detector is unverified-by-design (an
// Identifier-aware variant would have to read both halves from the chunk).
package crispchat

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Crisp plugin keys are documented as 40+ char base64url tokens.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,80})\b`)

var contextKeywords = []string{"crisp", "crisp_api", "crisp_token", "crisp.chat"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CrispChat }

func (Scanner) Keywords() []string { return []string{"crisp"} }

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
			DetectorType: detectors.CrispChat,
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
