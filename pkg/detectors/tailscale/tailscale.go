// Package tailscale detects Tailscale auth keys (`tskey-auth-…`) and API
// keys (`tskey-api-…`).
//
// Verify is intentionally not implemented for auth keys: they are
// provisioning credentials with no list-yourself endpoint — the only call
// that consumes them is `tailscale up`, which would actually join a node to
// the tailnet. Probing would be a destructive side effect, so we surface
// unverified-by-design.
//
// API keys (`tskey-api-…`) do have a /api/v2/tailnet endpoint that takes a
// tailnet name we don't know in advance, so they likewise surface unverified.
package tailscale

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `tskey-` is the documented prefix; `auth-` and `api-` are the two
// sub-types. Body is base32 / base62 of varying length (~22..64); we accept
// 20..96 to absorb format drift.
var tokenRe = regexp.MustCompile(`\b(tskey-(?:auth|api|client)-[A-Za-z0-9]{8,16}-[A-Za-z0-9]{20,96})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Tailscale }

func (Scanner) Keywords() []string { return []string{"tskey-"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Tailscale,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
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
