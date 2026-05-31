// Package launchnotes detects LaunchNotes API tokens.
//
// Verify is intentionally NOT performed — and crucially, NOT for the reason
// an earlier comment claimed ("every endpoint is destructive"). That claim is
// false: LaunchNotes' real GraphQL endpoint is the fixed
// https://app.launchnotes.io/graphql with a read-only `viewer { id }` query
// and read-only `public_…` tokens, so verification would not be destructive.
//
// The real blocker is token *shape*. Every piece of LaunchNotes' own
// documentation (help center + developer.launchnotes.com) shows read-only
// tokens prefixed `public_` (e.g. `public_QKHLUeWw6HxyE5cq9nujHqqX`). There is
// no public evidence LaunchNotes ever issues an `ln_`-prefixed credential, so
// building Verify on the legacy `ln_` regex would never produce Verified=true
// for a genuine token — it would only "verify nothing." That makes the `ln_`
// shape unverified-by-design (class b): it cannot be authoritatively confirmed
// as a LaunchNotes credential and it collides with arbitrary `ln_`-prefixed
// identifiers (math `ln_` constants, cache keys, minified-JS slugs).
//
// Hardening here re-anchors toward the documented `public_…` shape and keeps
// the speculative `ln_` shape only behind a context-vicinity gate plus an
// entropy gate, so a bare `ln_` token in unrelated code is dropped.
//
// FOLLOW-UP (class a): once the regex is re-anchored on the documented
// `public_` / management formats, Verify against app.launchnotes.io/graphql
// `viewer{id}` (200+data => valid, auth-error => invalid, 429 => unverified)
// becomes genuinely feasible.
package launchnotes

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// keyRe matches two shapes:
//
//   - `public_…` — the documented read-only LaunchNotes token shape. 20+
//     base62 chars. Captured directly; this is the authentic format.
//   - `ln_…` — a speculative/legacy shape. Kept only behind the vicinity +
//     entropy gates below because it collides with unrelated `ln_` identifiers.
//
// The left side uses an explicit non-word delimiter class instead of `\b` so a
// match cannot start mid-identifier (e.g. `lin_api_…` Linear, `learn_…`,
// `login_…`). Go's RE2 has no lookbehind, so the delimiter is a capture group
// (group 1) and the token is group 2.
var keyRe = regexp.MustCompile(`(^|[^A-Za-z0-9_])(public_[A-Za-z0-9]{20,64}|ln_[A-Za-z0-9]{32,64})`)

// Context keywords that must appear within vicinityWindow bytes of an `ln_`
// match for it to be emitted. `public_` tokens are distinctive enough on their
// own and do not require vicinity.
var contextRe = regexp.MustCompile(`(?i)launchnotes|launch_notes`)

const (
	// vicinityWindow is the byte radius around a speculative `ln_` match in
	// which a LaunchNotes context keyword must appear.
	vicinityWindow = 40
	// minBodyEntropy gates the post-prefix body of `ln_` tokens to reject
	// low-entropy filler like ln_aaaa… or ln_0123456789abcdef… repeats.
	minBodyEntropy = 3.5
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LaunchNotes }

func (Scanner) Keywords() []string { return []string{"ln_", "public_", "launchnotes"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// group 2 is the token (group 1 is the delimiter).
		token := string(data[h[4]:h[5]])
		if !accept(token, h[4], data) {
			continue
		}
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// accept applies the shape-specific gates.
//
//   - `public_…` : documented authentic shape, accepted directly.
//   - `ln_…`     : speculative — requires (1) a LaunchNotes context keyword
//     within vicinityWindow bytes and (2) a minimum-entropy body, to suppress
//     unrelated `ln_`-prefixed identifiers.
func accept(token string, tokenStart int, data []byte) bool {
	if strings.HasPrefix(token, "public_") {
		return true
	}
	// ln_ path.
	body := strings.TrimPrefix(token, "ln_")
	if !detectors.HasMinEntropy(body, minBodyEntropy) {
		return false
	}
	return hasContextNearby(tokenStart, len(token), data)
}

// hasContextNearby reports whether a LaunchNotes context keyword appears within
// vicinityWindow bytes on either side of [start, start+length).
func hasContextNearby(start, length int, data []byte) bool {
	lo := start - vicinityWindow
	if lo < 0 {
		lo = 0
	}
	hi := start + length + vicinityWindow
	if hi > len(data) {
		hi = len(data)
	}
	return contextRe.Match(data[lo:hi])
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
