// Package okta detects Okta API tokens (00... prefix + 40 URL-safe chars).
//
// Verify is intentionally not implemented. Okta's verify endpoint
// (/api/v1/users/me) lives on the customer's tenant URL
// (<tenant>.okta.com / .oktapreview.com), and we do not extract the tenant
// from the surrounding context reliably enough to probe it without risk
// of hitting the wrong tenant. The leak is still surfaced — operators
// should rotate immediately on any unverified hit.
package okta

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Okta tokens start with "00" then 40 URL-safe base64-ish chars (alphanum,
// underscore, hyphen). The shape is documented and stable.
var tokenRe = regexp.MustCompile(`\b(00[A-Za-z0-9_-]{40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Okta }

// "00" alone would prefilter every chunk that contains the digit pair (i.e.
// almost everything), so we anchor on "okta" instead. Operators who paste
// just the token into a config without the keyword will be missed — that's
// an acceptable trade for a usable prefilter.
func (Scanner) Keywords() []string { return []string{"okta"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
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
		// Verified=false by design — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Okta,
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
