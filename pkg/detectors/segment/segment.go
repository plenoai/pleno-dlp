// Package segment detects Segment write keys (32-char base62-ish).
//
// Verify is intentionally not implemented. Segment write keys cannot be
// validated without sending a track/identify event, which would pollute
// the customer's workspace with synthetic data and inflate their billed
// MTU. Surfacing the leak unverified is the correct behavior.
package segment

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 32 alphanumeric / underscore / hyphen — same shape as many ids, so the
// keyword gate is essential.
var tokenRe = regexp.MustCompile(`\b([a-zA-Z0-9_-]{32})\b`)

// keywordRe is the anchored Segment.com marker. The bare `segment`
// substring is everywhere in software docs ("HLS segment", "segment
// URI") and the token regex is `[a-zA-Z0-9_-]{32}` — UUIDs-without-
// dashes, MD5 hashes, opaque ids — match too. Require a Segment
// credential anchor.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bsegment[_\-](?:write|api|token|key|secret)` +
	`|\bsegment[_\-]?io\b` +
	`|\bsegment\.com\b` +
	`|\bsegmentio\b` +
	`|\bsegment_write_key\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Segment }

func (Scanner) Keywords() []string { return []string{"segment"} }

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
		// Verified=false by design — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Segment,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
