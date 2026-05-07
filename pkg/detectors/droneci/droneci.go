// Package droneci detects Drone CI personal access tokens (24-char alnum
// co-occurring with `drone` keyword).
//
// Verify is intentionally not implemented. Drone CI is self-hosted; the
// API endpoint depends on the operator's server URL (e.g. drone.example.com)
// which is rarely co-located with the token in code. We surface the leak
// unverified-by-design and let reviewers rotate.
package droneci

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 24-char alnum, the documented Drone token shape. Co-occurrence with
// `drone` keyword is mandatory because 24-char alnum is too generic to
// surface without context.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,32})\b`)

var contextKeywords = []string{"drone", "drone_token", "drone_secret", "drone_server", "drone.io"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DroneCI }

func (Scanner) Keywords() []string { return []string{"drone"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.DroneCI,
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
