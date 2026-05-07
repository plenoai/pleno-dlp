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

var contextKeywords = []string{"pusher_beams", "pusher.beams", "beams_secret", "beamsclient"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PusherBeams }

func (Scanner) Keywords() []string { return []string{"pusher_beams", "beams"} }

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
