// Package pusherbeams detects Pusher Beams secret keys — 32-hex strings
// near `pusher_beams` keyword. Distinct from PusherChannels (HMAC-signed
// per-app-id). Pusher Beams ships a server-side secret that authorizes
// the publish endpoint via Bearer auth. Verified via /publish_api/v1/
// instances/<instance_id>/publishes endpoint — but instance_id is not
// reliably in the chunk; we surface unverified-by-design.
package pusherbeams

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Pusher Beams secret keys are documented as 32-hex.
var tokenRe = regexp.MustCompile(`\b([a-fA-F0-9]{32})\b`)

// contextKeywords are the assignment-adjacent words that must appear close to
// the token. Deliberately excludes the bare word "beams" — a 32-hex shape is
// the single most common hash in source trees (MD5, hex checksums, dashless
// UUIDs, ETags, cache keys), so the gate has to be specific to Pusher Beams.
var contextKeywords = []string{"pusher_beams", "pusher.beams", "beams_secret", "beamsclient"}

// negativeKeywords mark the dominant 32-hex false-positive contexts. If any of
// these sits in the same vicinity window, the match is a hash/digest, not a
// secret — skip it even when a contextKeyword is also nearby.
var negativeKeywords = []string{"md5", "sha1", "sha256", "checksum", "integrity", "etag", "digest", "hash"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PusherBeams }

// Keywords drops the over-generic bare "beams" so chunks that only mention
// "sunbeams" / "light beams" never enter FromData. Every prefilter token here
// also appears in contextKeywords, keeping the prefilter and vicinity gate in
// lockstep.
func (Scanner) Keywords() []string {
	return []string{"pusher_beams", "beams_secret", "beamsclient"}
}

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
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy floor rejects all-repeated / low-variety hex placeholders
		// (e.g. "00000000..."). A genuine MD5 clears 3.0 comfortably, so this
		// is a secondary guard against obvious filler, not the primary gate.
		if !detectors.HasMinEntropy(token, 3.0) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PusherBeams,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword requires a Pusher-Beams context keyword within a tight 48-byte
// vicinity of the token and rejects the window if it also carries a hash/digest
// negative keyword. The narrow radius means a 32-hex value merely co-located in
// a large file no longer matches — the keyword must be assignment-adjacent.
func nearKeyword(lower string, start, end int) bool {
	const radius = 48
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, neg := range negativeKeywords {
		if strings.Contains(window, neg) {
			return false
		}
	}
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
