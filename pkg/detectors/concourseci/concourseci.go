// Package concourseci detects Concourse CI local user tokens (`fly login`
// bearer tokens, observed at 28+ chars URL-safe base64). Self-hosted by
// design — the verify endpoint isn't a fixed SaaS URL — so this detector
// surfaces under --unverified-results.
package concourseci

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{28,64})\b`)

// minEntropy gates against repeating / low-information placeholders.
// fly bearer tokens are random URL-safe base64 (alphabet ~64, ceiling ~6
// bits/char); hex digests/UUIDs land lower and doc dummies (`aaaa…`,
// repeating patterns) lower still. 3.5 is the base64url floor per
// detectors/entropy.go guidance.
const minEntropy = 3.5

// hexRe matches a candidate composed entirely of hex digits. Commit SHAs
// (40), md5 (32), sha256 (64) and dash-free UUIDs (32) all fall in the
// 28-64 length window and would otherwise pass — but a fly token is opaque
// base64url, not a hex digest, so an all-hex run is a lookalike, never the
// real secret.
var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

var contextKeywords = []string{
	"concourse",
	"concourse_ci",
	"concourse-ci",
	"fly_token",
	"concourse_token",
	"concourse_url",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ConcourseCI }

func (Scanner) Keywords() []string { return []string{"concourse"} }

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
		if !plausibleToken(token) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.ConcourseCI,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// plausibleToken applies the shape gates that distinguish an opaque fly
// bearer token from the lookalikes the broad regex admits:
//   - reject all-hex runs (commit SHA / md5 / sha digests / dash-free UUIDs)
//   - require at least one digit AND one letter (rejects all-alpha words and
//     all-digit runs)
//   - require Shannon entropy >= minEntropy (rejects repeating placeholders)
func plausibleToken(token string) bool {
	if hexRe.MatchString(token) {
		return false
	}
	var hasDigit, hasLetter bool
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		}
	}
	if !hasDigit || !hasLetter {
		return false
	}
	return detectors.HasMinEntropy(token, minEntropy)
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
