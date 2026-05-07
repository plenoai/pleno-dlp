// Package launchnotes detects LaunchNotes API keys (`ln_…`).
//
// Verify is intentionally not performed. LaunchNotes' write API is the only
// authenticated surface and every endpoint is destructive (creates/updates
// release notes). Probing would emit visible content; we surface
// unverified-by-design and let reviewers rotate. ExtraData captures the
// nearest `launchnotes` keyword so triage can confirm the leak shape.
package launchnotes

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `ln_` + 32+ base62 chars. The `ln_` prefix plus the suffix length
// distinguish from Linear's `lin_api_` and from arbitrary `ln_` shell
// variables — production tokens are 40+ chars in observed samples.
var keyRe = regexp.MustCompile(`\b(ln_[A-Za-z0-9]{32,64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LaunchNotes }

func (Scanner) Keywords() []string { return []string{"ln_"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.LaunchNotes,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
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
