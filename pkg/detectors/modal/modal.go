// Package modal detects Modal token-id (`ak-…`) + token-secret (`as-…`)
// pairs.
//
// Verify is intentionally not performed. Modal tokens are workspace-scoped
// and the API endpoint requires the workspace short-name. We don't have it
// in the chunk most of the time and probing the wrong workspace creates
// audit-log entries unrelated to the leak. We surface unverified-by-design
// at SeverityHigh so reviewers rotate; the engine's verified-implies-
// critical rule simply doesn't fire here.
//
// Token id is captured as Raw, secret as RawV2 — matches the rest of the
// codebase's RawV2-aware pair convention.
//
// Because `ak-`/`as-` are generic two-letter prefixes and `{20,}` alone is
// loose, both token bodies pass a semantic gate (looksRandom): a Shannon
// entropy floor plus a mixed-case-with-digit charset requirement. This
// suppresses dictionary-word/label concatenations (`ak-administratorsgroup`)
// and placeholder docs samples (`ak-1234567890abcdefghij`) that the regex
// would otherwise pair within the 1024-byte co-occurrence window.
package modal

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	idRe     = regexp.MustCompile(`\b(ak-[A-Za-z0-9]{20,})\b`)
	secretRe = regexp.MustCompile(`\b(as-[A-Za-z0-9]{20,})\b`)
)

// minBodyEntropy is the Shannon-entropy floor (bits/char) applied to the
// random body of each token (the part after the `ak-` / `as-` prefix).
// Real Modal tokens are random base62-ish strings; `ak-`/`as-` are common
// two-letter prefixes that collide with identifier/label concatenations
// (e.g. `ak-administratorsgroup`, `as-development-cluster`). 3.0 bits/char
// is the standard floor used by sibling loose-regex detectors.
const minBodyEntropy = 3.0

// looksRandom rejects token bodies that read like dictionary-word or
// placeholder concatenations rather than a random credential. We require:
//   - Shannon entropy >= minBodyEntropy (kills runs of zeros / `aaaa…`),
//   - at least one digit AND mixed case (kills all-lowercase word concats
//     like `administratorsgroup` and all-digit placeholders like
//     `1234567890abcdefghij`).
//
// body is the substring AFTER the `ak-` / `as-` prefix.
func looksRandom(body string) bool {
	if !detectors.HasMinEntropy(body, minBodyEntropy) {
		return false
	}
	var hasDigit, hasUpper, hasLower bool
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		}
	}
	return hasDigit && hasUpper && hasLower
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Modal }

func (Scanner) Keywords() []string { return []string{"ak-", "as-"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	ids := idRe.FindAllSubmatchIndex(data, -1)
	if len(ids) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
		// Without a companion secret the pair is unverifiable AND a bare
		// `ak-` shape is high false-positive (any short alphanumeric label).
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, m := range ids {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		// Entropy/charset gate on the id body (after the `ak-` prefix).
		if !looksRandom(id[len("ak-"):]) {
			continue
		}
		secret, ok := nearestSecret(m[2], data, secrets)
		if !ok {
			continue
		}
		// Same gate on the paired secret body (after the `as-` prefix).
		// A dictionary-word `as-…` lookalike paired with a real-looking
		// `ak-…` is almost certainly a coincidental co-occurrence.
		if !looksRandom(secret[len("as-"):]) {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Modal,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"token_id": id},
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestSecret(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		dist := abs(h[2] - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[h[2]:h[3]])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
