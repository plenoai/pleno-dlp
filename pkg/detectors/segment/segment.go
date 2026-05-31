// Package segment detects Segment write keys (32-char base62-ish).
//
// Verify is intentionally not implemented (class=b, unverified-by-design).
// The matched Raw secret is a *write key* — a write-only event-ingest
// credential, not a read/auth token. The only endpoint that accepts a write
// key is the tracking/ingest API, so verifying would (1) MINT a synthetic
// event into the customer's workspace and inflate their billed MTU, and
// (2) be meaningless anyway: api.segment.io returns HTTP 200 for both valid
// and invalid write keys (validity is resolved asynchronously downstream),
// so a verify would yield a FALSE Verified=true. Surfacing the leak
// unverified is the correct behavior.
//
// Because the token regex (`[a-zA-Z0-9_-]{32}`) is intentionally broad, the
// detector applies an entropy floor and pure-hex exclusion as a second-pass
// semantic gate (see FromData) so low-entropy lookalikes sitting near a
// Segment anchor do not surface as findings.
package segment

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 32 alphanumeric / underscore / hyphen — same shape as many ids, so the
// keyword gate is essential.
var tokenRe = regexp.MustCompile(`\b([a-zA-Z0-9_-]{32})\b`)

// hexRe matches a 32-char run that is *purely* hexadecimal (either case).
// MD5 digests and UUID-without-dashes both land in this set and are common
// next to Segment anchors (migration notes, cache keys). Real write keys are
// random base62 and almost always carry at least one non-hex character
// ([g-zG-Z]), so excluding pure-hex runs is a near-zero-false-negative filter.
var hexRe = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// minEntropy is the Shannon floor (bits/char) below which a 32-char candidate
// is rejected. Real Segment write keys are random base62 (~4.5+ bits/char);
// zeroed placeholders and repeated-char runs sit far below 3.0.
const minEntropy = 3.0

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
		// Semantic gate: even sitting next to a Segment anchor, low-entropy
		// 32-char lookalikes (zeroed/repeated placeholders) and pure-hex runs
		// (MD5 digests, UUID-without-dashes) are not write keys.
		if hexRe.MatchString(token) {
			continue
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
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
