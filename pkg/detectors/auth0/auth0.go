// Package auth0 detects Auth0 management API tokens (long JWT-shaped strings)
// when an Auth0-specific context token sits in a tight chunk window.
//
// This detector overlaps with the generic JWT detector: every Auth0 token IS
// a JWT. The context gate makes this detector additive — Auth0 hits are
// surfaced as Auth0 (with provider context) when they're identifiable as
// such, and the generic JWT detector keeps surfacing all other JWTs.
//
// Verify is intentionally not implemented (class-b, unverified-by-design).
// Auth0 management API tokens are audience-bound — the verification path lives
// at `https://<tenant>.auth0.com/api/v2/...` and the tenant slug is not in the
// captured bytes. The token alone is not enough to fix the verify host, and
// the JWT iss/aud claims are unreliable (custom domains; the token may be an
// end-user ID/access token for an arbitrary audience rather than a Management
// API token), so a derived host would risk a false Verified=true. We surface
// the leak unverified so operators rotate.
//
// Hardening over the previous "any JWT within 256 bytes of the substring
// auth0" rule:
//   - Require an Auth0-specific context token (auth0.com, <tenant>.auth0.com,
//     auth0_management, management.auth0) — not the bare substring "auth0",
//     which matches import paths like github.com/auth0/go-jwt-middleware.
//   - Shrink the proximity radius to 96 bytes.
//   - Gate on Shannon entropy of the signature segment to drop low-entropy
//     documentation / sample JWTs.
//   - Exclude the canonical RFC-7519 / jwt.io example JWT and unsigned
//     (alg:"none") tokens whose third segment is empty or trivial.
package auth0

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// JWT shape; same regex as the generic JWT detector. The context gate is
// what distinguishes this from a generic JWT hit.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

// auth0HostRe matches an Auth0 tenant host (<tenant>.auth0.com, with optional
// region like <tenant>.us.auth0.com) or a bare auth0.com / management.auth0
// reference. This is the tight, provider-specific context token — distinct
// from the bare substring "auth0" which appears in unrelated import paths.
var auth0HostRe = regexp.MustCompile(`(?i)(?:[a-z0-9][a-z0-9-]*\.)?auth0\.com|management\.auth0|auth0_management`)

// minSigEntropy drops documentation / sample JWTs whose signature segment is
// low-entropy filler (e.g. "signature_part_long_enough"). Real HMAC/RSA
// signatures are base64url over random bytes and sit well above this.
const minSigEntropy = 3.5

// canonical RFC-7519 / jwt.io example token. Pasted into READMEs and fixtures;
// never a real leak.
const rfc7519Example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Auth0 }

// "auth0" is the cheap prefilter; the precise auth0.com host / management
// context is enforced per-hit in FromData.
func (Scanner) Keywords() []string { return []string{"auth0"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := jwtRe.FindAllSubmatchIndex(data, -1)
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
		// Negative-lookalike exclusions: the canonical example and unsigned
		// tokens are never real Auth0 management tokens.
		if token == rfc7519Example || isUnsignedOrTrivial(token) {
			continue
		}
		// Entropy gate on the signature segment drops low-entropy sample JWTs.
		if !signatureHasEntropy(token) {
			continue
		}
		// Co-occurrence with an Auth0-specific host/context token within a
		// tight window is mandatory; otherwise this would duplicate every
		// generic JWT detector hit and fire on unrelated import paths.
		if !nearAuth0Context(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Auth0,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Unverified-by-design (class-b): Management-API identity is not
			// provable from the captured bytes alone, so we defer the severity
			// to the detector default rather than auto-tagging Critical.
			Severity: detectors.DefaultSeverity(detectors.Auth0, false),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isUnsignedOrTrivial reports whether the token's signature segment marks it as
// unsigned (alg:"none") with an empty/trivial third segment, or is otherwise
// too short to be a real signature. The regex guarantees >=10 chars in segment
// three, so we focus on the alg:"none" header shape.
func isUnsignedOrTrivial(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return true
	}
	// Decode the header is overkill; the base64url of {"alg":"none"...} starts
	// with the recognizable "eyJhbGciOiJub25lI" prefix regardless of trailing
	// header fields.
	if strings.HasPrefix(parts[0], "eyJhbGciOiJub25lI") {
		return true
	}
	return false
}

// signatureHasEntropy gates on the Shannon entropy of the signature segment.
func signatureHasEntropy(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	return detectors.HasMinEntropy(parts[2], minSigEntropy)
}

// nearAuth0Context reports whether an Auth0-specific host/context token sits
// within a tight window around the JWT match.
func nearAuth0Context(lower string, start, end int) bool {
	const radius = 96
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return auth0HostRe.MatchString(lower[from:to])
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
