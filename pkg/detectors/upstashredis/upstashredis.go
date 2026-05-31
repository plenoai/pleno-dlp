// Package upstashredis detects Upstash Redis REST tokens (long base64url near
// `upstash`).
//
// Verify is intentionally not performed. Upstash REST tokens are bound to
// a per-database host in the form `<region>-<name>-<id>.upstash.io` —
// the host isn't predictable from the token alone and we frequently don't
// see it in the same chunk. Probing a guessed host would either 401/404 or
// hit the wrong tenant, so a (Verified=false) from a mismatched host gives
// no signal. We surface unverified-by-design at class b and capture the
// host into ExtraData only when we see it in the same local vicinity as
// the token, to help triage.
//
// Hardening (class b kept): the raw token shape `[A-Za-z0-9]{50,128}` is
// extremely promiscuous — git SHAs, hex digests, other vendors' keys, and
// dot-stripped JWT/base64 blobs all match. We therefore:
//   - prefer the canonical `UPSTASH_REDIS_REST_TOKEN=<token>` assignment as
//     the high-confidence primary match;
//   - for the secondary (loose) path, require an Upstash-specific context
//     token (UPSTASH_REDIS_REST_TOKEN, UPSTASH_TOKEN, .upstash.io, or the
//     word `upstash`) within a tight ~64-byte radius rather than any broad
//     keyword in a 256-byte window;
//   - gate on Shannon entropy (>= 4.0 bits/char) and character-class
//     diversity (lower+upper+digit), which rejects all-hex digests,
//     all-decimal runs, and low-entropy dictionary/path-like runs;
//   - bind the captured host to the same local vicinity as the token so
//     ExtraData[host] is not misattributed from an unrelated `.upstash.io`
//     elsewhere in the chunk.
package upstashredis

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Canonical assignment form — highest confidence. The token immediately
// follows `UPSTASH_REDIS_REST_TOKEN` after `=`, `:`, whitespace, or quotes.
var primaryRe = regexp.MustCompile(`(?i)UPSTASH_REDIS_REST_TOKEN["']?\s*[=:]\s*["']?([A-Za-z0-9]{50,128})`)

// Loose token shape used for the secondary path. Gated heavily by
// entropy, diversity, and tight-vicinity context below.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{50,128})\b`)

// Database host capture, e.g. us1-test-12345.upstash.io.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.upstash\.io)\b`)

// minTokenEntropy rejects long but low-information runs (repeated patterns,
// dictionary/path-like blobs). Real Upstash REST tokens are high-entropy
// base64url and sit well above this.
const minTokenEntropy = 4.0

// vicinityRadius is the byte window (each side) searched for an
// Upstash-specific context token in the secondary path, and for the
// nearest host binding. Tight by design — a token genuinely belonging to
// Upstash sits right next to its env var / URL.
const vicinityRadius = 64

// contextTokens are Upstash-specific markers. Unlike the prior broad
// keyword set ("upstash" anywhere in 256 bytes), these are matched only
// within vicinityRadius bytes of the candidate token.
var contextTokens = []string{
	"upstash_redis_rest_token",
	"upstash_token",
	".upstash.io",
	"upstash",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.UpstashRedis }

func (Scanner) Keywords() []string { return []string{"upstash"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}

	emit := func(token string, tokStart, tokEnd int) {
		if _, dup := seen[token]; dup {
			return
		}
		if strings.Contains(token, ".upstash.io") {
			return
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host := nearestHost(lower, tokStart, tokEnd); host != "" {
			extra["host"] = host
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.UpstashRedis,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		})
	}

	// Primary: canonical assignment form. Highest confidence — still apply
	// the diversity/entropy gate to reject obviously templated placeholders.
	for _, m := range primaryRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[m[2]:m[3]])
		if !looksLikeToken(token) {
			continue
		}
		emit(token, m[2], m[3])
	}

	// Secondary: loose token shape, gated by entropy + diversity + a tight
	// Upstash-specific context token nearby.
	for _, m := range tokenRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !looksLikeToken(token) {
			continue
		}
		if !nearContext(lower, m[2], m[3]) {
			continue
		}
		emit(token, m[2], m[3])
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// looksLikeToken applies the entropy + character-class diversity gate.
// Real Upstash REST tokens are high-entropy base64url containing a mix of
// lowercase, uppercase, and digits. This rejects:
//   - all-hex runs (commit SHAs, md5/sha digests),
//   - all-decimal runs,
//   - low-entropy dictionary/path-like or repeated patterns.
func looksLikeToken(token string) bool {
	if !detectors.HasMinEntropy(token, minTokenEntropy) {
		return false
	}
	var hasLower, hasUpper, hasDigit bool
	for i := 0; i < len(token); i++ {
		switch c := token[i]; {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	return hasLower && hasUpper && hasDigit
}

// nearContext reports whether an Upstash-specific context token appears
// within vicinityRadius bytes of [start,end).
func nearContext(lower string, start, end int) bool {
	window := vicinity(lower, start, end)
	for _, kw := range contextTokens {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// nearestHost returns the `.upstash.io` host within the token's local
// vicinity, or "" if none — so the host is bound to this token rather than
// taken from an unrelated database elsewhere in the chunk.
func nearestHost(lower string, start, end int) string {
	return hostRe.FindString(vicinity(lower, start, end))
}

func vicinity(lower string, start, end int) string {
	from := start - vicinityRadius
	if from < 0 {
		from = 0
	}
	to := end + vicinityRadius
	if to > len(lower) {
		to = len(lower)
	}
	return lower[from:to]
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
