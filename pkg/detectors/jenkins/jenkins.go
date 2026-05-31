// Package jenkins detects Jenkins API tokens — the modern shape is
// `11<32-hex>` (a single 34-char hex string starting with `11`) issued by
// the Jenkins user "Configure" page. Jenkins is self-hosted, so the
// controller URL is not in the chunk and we cannot probe; additionally the
// token is only the *password* half of HTTP Basic auth (`user:apiToken`)
// and we never extract the username, so a token-only Verify cannot
// authenticate correctly. Surfaces unverified-by-design (class b).
//
// Hardening: the bare word `jenkins` saturates build logs and workspaces,
// which are full of 34-char hex slices (git SHA fragments, artifact
// checksums, content-addressed cache keys). A 256-byte proximity to the
// word `jenkins` is therefore far too loose. We instead require the token
// to be a credential *assignment*: a credential-specific key
// (`jenkins_api_token`, `jenkins_token`, …) immediately followed by `:` or
// `=` and then the `11<32-hex>` value. The bare `jenkins` keyword is kept
// only as the cheap engine prefilter, never as a match-licensing context.
// A Shannon-entropy floor rejects low-information hex (repeated nibbles,
// long zero runs) that satisfies the hex class but is not a real token.
package jenkins

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// assignRe matches only when the 11<32-hex> value is assigned to a
// credential-specific Jenkins key within a few bytes. The leading
// alternation enumerates the accepted key forms (api token / token / user
// token / password), all optionally with a quote/whitespace before the
// `:` or `=` operator. The trailing `\b` plus the fixed 34-char length
// means a 40-char git SHA or 64-char SHA-256 slice cannot be captured: a
// longer hex run fails the closing word boundary.
var assignRe = regexp.MustCompile(
	`(?i)(?:jenkins[_\-]?(?:api[_\-]?)?token|jenkins[_\-]?user[_\-]?(?:api[_\-]?)?token|jenkins[_\-]?(?:user[_\-]?)?password)` +
		`["']?\s*[:=]\s*["']?` +
		`\b(11[0-9a-f]{32})\b`,
)

// minEntropy floors out hex like 1100000000000000000000000000000000 or
// repeated-nibble checksums (alphabet ceiling for hex is ~4.0 bits/char).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jenkins }

// Keywords keeps only the bare provider word as the engine prefilter. It is
// NOT used to license a match — the assignment regex enforces a
// credential-specific key. This is intentional: an empty keyword set would
// force the full regex over every chunk.
func (Scanner) Keywords() []string { return []string{"jenkins"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := assignRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// Group 1 is the token capture.
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
