// Package spinnaker detects Spinnaker (Netflix) API tokens (40-char base62 or
// JWT-shaped) gated on the `spinnaker` keyword window. Spinnaker is always
// self-hosted (Gate API host varies per deployment), so verification is
// unverified-by-design — keyword + shape gating bound the false-positive rate.
package spinnaker

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_.-]{20,}|[A-Za-z0-9]{40,80})\b`)

// keywordRe is the anchored Spinnaker marker. The bare substring
// `spinnaker` appears in any reference to the upstream project URL
// (`github.com/spinnaker/spinnaker.git`), which sits adjacent to
// commit SHA-1 hashes in test fixtures — a hard 40-hex FP. Require
// a Spinnaker credential anchor (`spinnaker_api`, `gate.spinnaker`,
// `spinnaker.io`, `SPINNAKER=`) instead.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bspinnaker[_\-](?:api|token|key|secret|gate|auth)\b` +
	`|\bgate\.spinnaker\b` +
	`|\bspinnaker\.io\b` +
	`|\bspinnaker[ \t]*[:=]` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Spinnaker }

func (Scanner) Keywords() []string { return []string{"spinnaker"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Spinnaker,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
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
