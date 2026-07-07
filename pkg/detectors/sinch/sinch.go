// Package sinch detects Sinch API keys (UUIDs) gated on an assignment-style
// `sinch` keyword in close proximity. Sinch's authenticated endpoints require
// both the API key and a project_id (and pick a regional host
// us./eu.sms.api.sinch.com) — without both we can't send a probe request, so
// this surfaces unverified-by-design (class=b).
//
// The token shape is a bare lowercase UUID, which is ubiquitous (request/
// trace ids, message/batch/contact ids, the project_id itself, SDK-doc
// example GUIDs). To keep this from over-matching, FromData applies three
// semantic gates beyond the raw shape:
//
//  1. Proximity: the UUID must sit within a tight 64-byte window of an
//     assignment-style Sinch context keyword (sinch_api_key / sinch_key /
//     sinch_token, or `sinch` immediately followed by key/token/=), not the
//     bare brand word anywhere in a wide window.
//  2. Entropy: the dash-stripped hex payload must clear a Shannon floor
//     (~3.0 bits/char), dropping sequential / low-variety placeholder UUIDs
//     while keeping real random hex keys.
//  3. Lookalike exclusion: all-zero, single-repeated-nibble, and obviously
//     sequential placeholder UUIDs are rejected outright.
package sinch

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

// keywordRe is the anchored, assignment-style Sinch credential marker. The
// bare brand word `sinch` co-occurs within 256 bytes of an unrelated UUID far
// too often, so we require the UUID to be adjacent to a key/token assignment
// context:
//
//	sinch_api_key / sinch_key / sinch_token (any separator/case), or
//	`sinch` immediately followed by key|token|secret or an `=` assignment.
var keywordRe = regexp.MustCompile(`(?i)\bsinch[_\-\s]*(?:api[_\-\s]*)?(?:key|token|secret)\b|\bsinch\s*[:=]`)

// minEntropy is the Shannon floor (bits/char) for the dash-stripped 32-hex
// payload. Real random hex keys clear ~3.5+ bits/char; sequential or
// low-variety placeholder UUIDs sit well below 3.0.
const minEntropy = 3.0

// proximity radius around the keyword span, in bytes. Tightened from 256 to
// 64 so the UUID must genuinely belong to the assignment, not merely share a
// log line / config block with it.
const radius = 64

// sequentialHex matches the ascending nibble run that headlines doc-example
// UUIDs (e.g. 12345678-...). Such tokens are placeholders, not credentials.
var sequentialHex = regexp.MustCompile(`^(?:0123456789abcdef|0123456789)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Sinch }

func (Scanner) Keywords() []string { return []string{"sinch"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		// Strip dashes to score the raw hex payload only.
		hex := strings.ReplaceAll(token, "-", "")
		if isLookalike(hex) {
			continue
		}
		if !detectors.HasMinEntropy(hex, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		// Verified=false by design — see package doc (class=b).
		out = append(out, detectors.Result{
			DetectorType: detectors.Sinch,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isLookalike rejects placeholder UUIDs that match the shape but cannot be
// credentials: all-zero, a single repeated nibble, or an obviously sequential
// leading run.
func isLookalike(hex string) bool {
	if hex == "" {
		return true
	}
	first := hex[0]
	allSame := true
	for i := 0; i < len(hex); i++ {
		if hex[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}
	if sequentialHex.MatchString(hex) {
		return true
	}
	// Leading ascending decimal run such as 12345678.
	if strings.HasPrefix(hex, "12345678") {
		return true
	}
	return false
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
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
