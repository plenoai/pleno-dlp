// Package jenkins detects Jenkins API tokens — the modern shape is
// `11<32-hex>`, issued by the Jenkins user "Configure" page. Jenkins is
// self-hosted, so the controller URL is not in the chunk and we cannot probe;
// the token is also only the password half of HTTP Basic auth and we never
// extract the username, so a token-only Verify cannot authenticate. Surfaces
// unverified-by-design (class b).
//
// The bare word `jenkins` saturates build logs full of 34-char hex slices, so
// a proximity gate is too loose. We instead require a credential assignment: a
// credential-specific key immediately followed by `:` or `=` and then the
// `11<32-hex>` value. The bare `jenkins` keyword is kept only as the engine
// prefilter. A Shannon-entropy floor rejects low-information hex.
package jenkins

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// assignRe matches only when the 11<32-hex> value is assigned to a
// credential-specific Jenkins key within a few bytes. The trailing `\b` plus
// the fixed 34-char length means a longer git SHA or SHA-256 slice cannot be
// captured — the closing word boundary fails.
var assignRe = regexp.MustCompile(
	`(?i)(?:jenkins[_\-]?(?:api[_\-]?)?token|jenkins[_\-]?user[_\-]?(?:api[_\-]?)?token|jenkins[_\-]?(?:user[_\-]?)?password)` +
		`["']?\s*[:=]\s*["']?` +
		`\b(11[0-9a-f]{32})\b`,
)

// minEntropy floors out low-information hex (repeated nibbles, long zero runs).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jenkins }

// Keywords keeps only the bare provider word as the engine prefilter; it does
// not license a match — the assignment regex enforces a credential-specific
// key.
func (Scanner) Keywords() []string { return []string{"jenkins"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := assignRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Jenkins,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
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
