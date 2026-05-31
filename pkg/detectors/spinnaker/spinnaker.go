// Package spinnaker detects Spinnaker (Netflix) API tokens (40-80 char base62
// or JWT-shaped) gated on an assignment-style `spinnaker` credential anchor.
// Spinnaker is always self-hosted (the auth-bearing Gate API host varies per
// deployment and is not derivable from the token), so verification is
// unverified-by-design: a bare base62 blob / JWT is not a routable Gate URL,
// and Gate's /auth/user is session/OAuth-based and returns 200 for the
// anonymous user on common configs — a wrong auth scheme would yield a false
// Verified=true. Keyword + shape + entropy gating bound the false-positive
// rate instead.
package spinnaker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// tokenRe matches the two shapes Spinnaker bearer credentials take: a JWT
// (eyJ-prefixed) or an opaque 40-80 char base62 string. Both branches are
// intentionally broad; the FP-bounding work is done post-match in isToken.
var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_.-]{20,}|[A-Za-z0-9]{40,80})\b`)

// pureHexRe matches a string that is *only* hex digits — 40-char git SHA-1,
// 64-char sha256 image digests, md5 sums. These are the dominant base62-branch
// false positives and carry no Spinnaker credential semantics.
var pureHexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// keywordRe is the anchored Spinnaker credential marker. A bare `spinnaker.io`
// URL reference is deliberately NOT an anchor: URL references co-occur with
// image digests (`spinnaker.io/clouddriver@sha256:...`), not secrets. Require
// an assignment-style credential context instead.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bspinnaker[_\-](?:api|token|key|secret|auth)\b` +
	`|\bgate\.spinnaker\b` +
	`|\bspinnaker[ \t]*[:=]` +
	`)`)

// minEntropy is the bits/char floor for the base62 branch. Repeated YAML keys,
// dotted identifiers, and structured hex-ish runs fall below ~3.5 for a 62-char
// alphabet (ceiling ≈ 6.0).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Spinnaker }

func (Scanner) Keywords() []string { return []string{"spinnaker"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !isToken(token) {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Spinnaker,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isToken applies the semantic gates that separate a plausible Spinnaker
// bearer credential from the structured-string noise the broad regex admits.
func isToken(token string) bool {
	if strings.HasPrefix(token, "eyJ") {
		return isJWT(token)
	}
	// base62 branch: reject pure-hex (git SHA-1 / sha256 digest / md5) and
	// low-entropy structured identifiers.
	if pureHexRe.MatchString(token) {
		return false
	}
	return detectors.HasMinEntropy(token, minEntropy)
}

// isJWT requires a structurally valid 3-segment JWT whose header is a
// base64url-decodable JSON object containing an `alg` claim. This excludes
// base64 config payloads that merely happen to start with `eyJ`.
func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	_, ok := header["alg"]
	return ok
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
	// Tightened from 96 to 40 bytes: an assignment anchor sits immediately
	// adjacent to its value, whereas image digests trail their URL anchor by
	// a longer span.
	const radius = 40
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
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
