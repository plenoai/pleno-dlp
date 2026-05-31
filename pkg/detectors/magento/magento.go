// Package magento detects Magento (Adobe Commerce) admin access
// tokens (32-char alnum). Surface only when a `magento` keyword AND a
// credential-context term are in close proximity so the broad alnum
// shape doesn't trigger universally.
//
// Unverified by design (class b). Live verification is infeasible: the
// raw secret is a bare 32-char [a-z0-9] string carrying zero host
// information, and Magento exposes at least three shape-indistinguishable
// 32-char token kinds (admin integration token, admin user bearer token,
// customer token), so no single endpoint can confirm validity without
// risking a false Verified=true. See docs/verify-coverage.md.
//
// The naive `\b[a-z0-9]{32}\b` shape collides with MD5/SHA hex digests,
// which Magento itself emits everywhere (cache keys, form keys, media
// and config hashes) right next to the literal word "magento". To keep
// the false-positive rate controlled we additionally:
//   - reject pure-hex lookalikes (require >=1 letter outside [a-f]),
//   - apply a Shannon-entropy floor, and
//   - require a credential-context term within a tight window.
package magento

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([a-z0-9]{32})\b`)

// hasNonHexLetter reports whether the token contains at least one letter
// in [g-z]. MD5/SHA hex digests live entirely in [a-f0-9]; a real
// admin/integration token uses the full [a-z0-9] alphabet and in
// practice contains such a letter. This rejects hash lookalikes.
var hasNonHexLetter = regexp.MustCompile(`[g-z]`)

// credentialContext matches a term that signals an actual credential
// assignment near the token, on top of the mandatory `magento` keyword.
var credentialContext = regexp.MustCompile(`(?i)token|access|api[_-]?key|bearer|integration|secret`)

// minEntropy is the bits/char floor for a 32-char alnum token. Pure
// structured/low-entropy strings (e.g. repeated runs) fall below this.
const minEntropy = 3.0

// magentoRadius is the window (bytes) the literal `magento` keyword must
// appear within; credentialRadius is the tighter window the credential
// context term must appear within.
const (
	magentoRadius    = 128
	credentialRadius = 64
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Magento }

func (Scanner) Keywords() []string { return []string{"magento"} }

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
		// Negative-lookalike exclusion: drop MD5/SHA hex digests.
		if !hasNonHexLetter.MatchString(token) {
			continue
		}
		// Entropy floor: drop low-information structured strings.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// Require the `magento` keyword AND a credential-context term in
		// proximity; `magento` alone fires on hex digests in Magento logs.
		if !nearKeyword(lower, h[2], h[3], "magento", magentoRadius) {
			continue
		}
		if !nearContext(lower, h[2], h[3], credentialRadius) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Magento,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
}

func windowBounds(textLen, start, end, radius int) (int, int) {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > textLen {
		to = textLen
	}
	return from, to
}

func nearKeyword(lower string, start, end int, kw string, radius int) bool {
	from, to := windowBounds(len(lower), start, end, radius)
	return strings.Contains(lower[from:to], kw)
}

func nearContext(lower string, start, end, radius int) bool {
	from, to := windowBounds(len(lower), start, end, radius)
	return credentialContext.MatchString(lower[from:to])
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
