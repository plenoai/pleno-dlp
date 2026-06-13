// Package generic detects high-entropy strings near credential keywords.
package generic

import (
	"context"
	"math"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// secretShape captures candidate secrets for entropy evaluation.
var secretShape = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,128}`)

// keywordRadius bounds the distance between keyword and secret.
const keywordRadius = 256

// minEntropy is the Shannon entropy floor.
const minEntropy = 4.0

// keywords gate generic detection to credential-shaped contexts.
var keywords = []string{
	"api_key",
	"apikey",
	"api-key",
	"access_key",
	"access-key",
	"accesskey",
	"secret_key",
	"secret-key",
	"secretkey",
	"private_key",
	"private-key",
	"privatekey",
	"client_secret",
	"client-secret",
	"clientsecret",
	"auth_token",
	"auth-token",
	"authtoken",
	"bearer ",
	"bearer:",
	"x-api-key",
	"x-auth-token",
	"password",
	"passwd",
	"credential",
	"token=",
	"token:",
	"token ",
	"secret=",
	"secret:",
	"signing_secret",
	"signing-secret",
	"webhook_secret",
	"webhook-secret",
	"webhooksecret",
	"private_token",
	"private-token",
	"privatetoken",
	"auth=",
	"auth:",
	"authorization:",
	"x-secret",
	"x-token",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GenericHighEntropy }

func (Scanner) Keywords() []string { return keywords }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !hasSecretShapeRun(data) {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	keywordSpans := keywordPositions(lower)
	if len(keywordSpans) == 0 {
		return nil, nil
	}

	matches := secretShape.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		secret := string(data[m[0]:m[1]])
		if _, dup := seen[secret]; dup {
			continue
		}
		if shannonEntropy(secret) < minEntropy {
			continue
		}
		if looksLikeIdentifier(secret) || looksLikePath(secret) {
			continue
		}
		if looksLikeSRIHash(secret) || looksLikeHexDigest(secret) {
			continue
		}
		if !nearKeyword(m[0], m[1], keywordSpans) {
			continue
		}
		seen[secret] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.GenericHighEntropy,
			Raw:          []byte(secret),
			Redacted:     redact(secret),
			ExtraData: map[string]string{
				"detector_kind": "generic-high-entropy",
			},
		})
	}
	return out, nil
}

// keywordPositions returns the start offsets of every keyword hit.
func keywordPositions(lower string) []int {
	var spans []int
	for _, kw := range keywords {
		idx := 0
		for {
			rel := strings.Index(lower[idx:], kw)
			if rel < 0 {
				break
			}
			spans = append(spans, idx+rel)
			idx += rel + len(kw)
		}
	}
	return spans
}

// nearKeyword reports whether the candidate lies within keywordRadius.
func nearKeyword(secretStart, secretEnd int, keywordStarts []int) bool {
	for _, k := range keywordStarts {
		// Distance is the gap between the closer pair of endpoints.
		switch {
		case k <= secretStart && secretStart-k <= keywordRadius:
			return true
		case k >= secretEnd && k-secretEnd <= keywordRadius:
			return true
		case k > secretStart && k < secretEnd:
			return true
		}
	}
	return false
}

// hasSecretShapeRun reports whether data contains a plausible candidate run.
func hasSecretShapeRun(data []byte) bool {
	const minLen = 20
	run := 0
	for _, c := range data {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '_' || c == '-' {
			run++
			if run >= minLen {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// looksLikeIdentifier reports whether s looks like a source-code
// identifier (CamelCase, snake_case, or mixed like Go's
// `TestSign_buildCanonicalHeaders`) rather than a random token.
//
// Real secrets virtually always contain digits or base64-marker chars
// (`+` / `/` / `=`) or random URL-safe punctuation (`-`); Go and most
// other languages' identifiers are confined to `[A-Za-z_]`. So the
// rule is: a run of length 20+ that uses ONLY letters and underscores
// is overwhelmingly an identifier, regardless of camel boundaries.
//
// `CredentialProviderOptions` → letters only → identifier.
// `TestSign_buildCanonicalHeadersContentLengthPresent` → letters+`_` → identifier.
// `Hf83KdjL9qZ8xVnB2Wm7TpRc` → has digits → not flagged here.
// `AKIAIOSFODNN7EXAMPLE` → has digit `7` → not flagged here.
// `ghp_aBcDeF123XYZ` → has digits → not flagged here.
func looksLikeIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_':
		default:
			return false
		}
	}
	return true
}

// looksLikePath reports whether s contains ≥ 2 forward-slash
// separators, which on real codebases mark an embedded URL or
// import path (e.g. `com/aws/aws-sdk-go-v2/aws`) rather than a
// base64-encoded secret. A base64 token may carry at most one `/`
// in practice; two or more is overwhelmingly path-shaped.
func looksLikePath(s string) bool {
	slashes := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			slashes++
			if slashes >= 2 {
				return true
			}
		}
	}
	return false
}

// looksLikeSRIHash reports whether s is a Subresource Integrity (SRI) hash.
// SRI hashes begin with sha256-, sha384-, or sha512- followed by base64;
// they appear in HTML integrity attributes and npm/yarn lock files and are
// never API secrets.
func looksLikeSRIHash(s string) bool {
	lower := strings.ToLower(s)
	for _, prefix := range []string{"sha256-", "sha384-", "sha512-"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// hexDigestLengths are the byte lengths of standard cryptographic digests
// (MD5=32, SHA-1=40, SHA-224=56, SHA-256=64, SHA-512=128).
var hexDigestLengths = map[int]bool{32: true, 40: true, 56: true, 64: true, 128: true}

// looksLikeHexDigest reports whether s is a lowercase/uppercase hex string of
// a standard hash length. Such strings appear as checksums in lock files
// (composer.lock, package-lock.json) and git object IDs; they are not secrets.
func looksLikeHexDigest(s string) bool {
	if !hexDigestLengths[len(s)] {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// shannonEntropy in bits-per-byte. Same shape as
// pkg/detectors/custom.shannonEntropy but inlined so the generic
// detector has no cross-package coupling — they evolved independently
// and we don't want a future tweak to one to silently change the other.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]int, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// redact preserves the first 4 chars and trims the rest. Generic hits
// don't have a known prefix structure (it's by definition unknown), so
// the simplest possible redaction is also the safest.
func redact(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
