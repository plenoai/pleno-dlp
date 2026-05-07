// Package grafana detects Grafana service-account tokens (`glsa_<32>_<8 hex>`).
//
// Verify is intentionally not implemented. Grafana service-account tokens are
// scoped to a specific Grafana host (self-hosted, Grafana Cloud, regional
// stacks). The host isn't predictable from the token shape and rarely sits
// next to it in source — probing the wrong host would silently fail or hit
// the wrong tenant. Tokens surface unverified-by-design.
package grafana

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Documented shape: `glsa_` + 32 base62 + `_` + 8 lowercase hex.
var tokenRe = regexp.MustCompile(`\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Grafana }

func (Scanner) Keywords() []string { return []string{"glsa_"} }

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
		out = append(out, detectors.Result{
			DetectorType: detectors.Grafana,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
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
