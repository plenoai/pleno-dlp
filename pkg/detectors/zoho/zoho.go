// Package zoho detects Zoho OAuth refresh tokens of the shape
// `1000.<base62>.<base62>` gated on the `zoho` keyword window.
//
// Unverified-by-design (class b). A bare refresh token is not a
// credential any Zoho endpoint accepts: the refresh-token grant
// (POST /oauth/v2/token grant_type=refresh_token) mandates client_id +
// client_secret in addition to the token, neither of which is captured
// in Raw. Verifying with only the refresh token would return
// invalid_client and falsely report Verified=false on genuinely live
// tokens. The region argument is secondary: the OAuth endpoint is
// region-specific (accounts.zoho.com / .eu / .in / .com.au / .jp) so
// verification would also require guessing the customer's data residency.
//
// The 1000.<base62>.<base62> shape is structurally generic (dotted
// blobs), so detection is semantically hardened: each base62 segment
// must clear a Shannon entropy floor, must not be entirely decimal
// (millis/IDs) or entirely lowercase-hex (build digests), and a `zoho`
// context keyword must sit adjacent to the match.
package zoho

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Capture the two base62 segments individually so each can be gated on
// entropy and lookalike exclusions.
var tokenRe = regexp.MustCompile(`\b1000\.([A-Za-z0-9]{32,})\.([A-Za-z0-9]{32,})\b`)

var contextKeywords = []string{"zoho", "zoho_refresh", "zoho_token", "zoho_oauth"}

// Real Zoho refresh-token segments are mixed-case base62. minSegmentEntropy
// rejects padded/placeholder blobs that pass the {32,} length check but
// carry almost no information.
const minSegmentEntropy = 3.5

var (
	allDecimalRe = regexp.MustCompile(`^[0-9]+$`)
	allHexRe     = regexp.MustCompile(`^[0-9a-f]+$`)
)

// plausibleSegment rejects lookalikes: all-decimal (timestamps/IDs),
// all-lowercase-hex (build hashes/digests), and low-entropy padding.
func plausibleSegment(seg string) bool {
	if allDecimalRe.MatchString(seg) || allHexRe.MatchString(seg) {
		return false
	}
	return detectors.HasMinEntropy(seg, minSegmentEntropy)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zoho }

// Keywords gates on "zoho" only. The bare "1000." prefix is dropped: a
// generic 1000.<blob>.<blob> with no zoho context must not enter the
// regex path, matching the in-detector nearKeyword requirement.
func (Scanner) Keywords() []string { return []string{"zoho"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// h[0:2] full match, h[2:4] segment 1, h[4:6] segment 2.
		token := string(data[h[0]:h[1]])
		if _, dup := seen[token]; dup {
			continue
		}
		seg1 := string(data[h[2]:h[3]])
		seg2 := string(data[h[4]:h[5]])
		if !plausibleSegment(seg1) || !plausibleSegment(seg2) {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Zoho,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword requires a zoho context keyword within a tight 64-byte
// vicinity (assignment-line proximity) rather than merely co-located in
// the same chunk. Every contextKeyword contains "zoho", so a generic
// 1000.<blob>.<blob> with no nearby zoho context is rejected.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
