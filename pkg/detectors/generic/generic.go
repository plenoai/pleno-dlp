// Package generic detects high-entropy strings near credential keywords.
package generic

import (
	"bytes"
	"context"
	"encoding/base64"
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
		// Hash-dense PHP/JS context gating (#249): these five checks
		// target the false-positive classes measured on laravel/framework
		// and axios/axios — bcrypt/argon2 password-hash fixtures,
		// algorithm-name test identifiers, bundler content-hash
		// filenames, MIME-type strings, and base64-encoded doc examples.
		// None of them touch the keyword-radius gate below; a candidate
		// still needs a nearby credential keyword to reach this point.
		if looksLikeCryptHashFragment(data, m[0], m[1]) {
			continue
		}
		if looksLikeIdentifierWithAlgoName(secret) {
			continue
		}
		if looksLikeBundlerAssetFilename(secret, data, m[1]) {
			continue
		}
		if looksLikeMimeType(secret) {
			continue
		}
		if decodesToPrintableText(secret) {
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

// cryptHashMarkerRE matches the fixed algorithm markers used by PHP/Unix
// crypt(3)-family password-hash formats: bcrypt ($2a$/$2b$/$2x$/$2y$),
// Argon2 (i/d/id), classic crypt (md5=$1$, sha256=$5$, sha512=$6$), and
// pbkdf2. Wherever one of these appears, the surrounding entropy run is
// unmistakably a hash literal from a hashing-library test fixture — never
// a live secret.
var cryptHashMarkerRE = regexp.MustCompile(`\$(2[abxy]|argon2(?:id|i|d)|1|5|6|pbkdf2(?:-sha\d+)?)\$`)

// cryptHashLookback bounds how far back from a candidate's start we scan
// for a crypt-format marker. bcrypt/argon2 hash literals are at most
// ~100 bytes end to end (cost/params + salt + hash), so a marker further
// back belongs to unrelated text.
const cryptHashLookback = 100

// looksLikeCryptHashFragment reports whether data[start:end] is a fragment
// of a known password-hash-function output rather than a raw secret. It
// covers two shapes seen in real hashing test suites (laravel/framework's
// EloquentModelHashedCastingTest.php and HasherTest.php, both firing 14+
// GenericHighEntropy hits before this fix):
//
//  1. A recognized algorithm marker ($2y$, $argon2i$, ...) appears within
//     cryptHashLookback bytes before the candidate. bcrypt/argon2 payloads
//     contain `.` or `,` which the secret-shape regex doesn't span, so one
//     hash literal is often split into 2-3 separate candidates — the
//     lookback catches every piece, not just the one right after the
//     marker.
//  2. The candidate is sandwiched directly between two literal `$`
//     characters (`$xxxx$`) — the generic shape of any crypt(3)-family
//     salt/hash segment, independent of a recognized algorithm name. Real
//     secrets are essentially never written wrapped bare in `$`.
func looksLikeCryptHashFragment(data []byte, start, end int) bool {
	lbStart := start - cryptHashLookback
	if lbStart < 0 {
		lbStart = 0
	}
	if cryptHashMarkerRE.Match(data[lbStart:start]) {
		return true
	}
	if start > 0 && end < len(data) && data[start-1] == '$' && data[end] == '$' {
		return true
	}
	return false
}

// algoNameTokenRE matches digit-bearing algorithm/encoding names that
// commonly appear inside otherwise-alphabetic camelCase identifiers, e.g.
// laravel/framework's HasherTest.php method names testBasicArgon2iHashing
// and testBasicArgon2idHashing. looksLikeIdentifier already rejects
// all-letter runs, but a single embedded digit (the "2" in Argon2)
// deliberately defeats that check so real digit-bearing secrets keep
// firing (see looksLikeIdentifier's doc comment) — this closes that gap
// for the specific, bounded set of algorithm names rather than loosening
// the digit tolerance generally, which would swallow real secrets like
// AKIAIOSFODNN7EXAMPLE or ghp_aBcDeF123XYZ.
var algoNameTokenRE = regexp.MustCompile(`(?i)sha512|sha384|sha256|sha224|sha1|md5|md4|base64|base58|base32|aes256|aes192|aes128|argon2id|argon2i|argon2d|pbkdf2|utf8|utf16|rsa2048|rsa4096|crc32|hmac256|hmac512`)

// looksLikeIdentifierWithAlgoName strips known algorithm-name tokens from
// s and re-checks looksLikeIdentifier on what's left. If s contains none
// of the tokens, it returns false unconditionally — this function only
// ever narrows an existing gap, never widens looksLikeIdentifier's own
// behavior for strings that don't mention a known algorithm name.
func looksLikeIdentifierWithAlgoName(s string) bool {
	stripped := algoNameTokenRE.ReplaceAllString(s, "")
	if stripped == s {
		return false
	}
	return looksLikeIdentifier(stripped)
}

// staticAssetExtensions are the extensions bundler-emitted (Vite/webpack)
// content-hashed filenames use: `<Name>-<8-10 char build hash>.<ext>`.
// Build manifests (Vite's manifest.json) list dozens of these per file;
// each hash suffix passes the entropy and keyword-radius gates on its own
// (laravel/framework's tests/Foundation/fixtures/prefetching-manifest.json
// fired 6 GenericHighEntropy hits before this fix, all this shape).
var staticAssetExtensions = []string{
	".js", ".mjs", ".cjs", ".css", ".vue", ".map", ".json",
	".woff", ".woff2", ".png", ".svg", ".ts", ".tsx",
}

// looksLikeBundlerAssetFilename reports whether the candidate at
// data[:end] is a bundler content-hash filename: it requires a hyphen
// (the `<Name>-<hash>` separator — real secrets of this length rarely
// contain one) AND a recognized static-asset extension immediately
// following the match. Requiring both keeps this narrow: a hyphenated
// token that ISN'T followed by a file extension (e.g. a real hyphenated
// API key) is left alone.
func looksLikeBundlerAssetFilename(secret string, data []byte, end int) bool {
	if !strings.ContainsRune(secret, '-') {
		return false
	}
	rest := data[end:]
	for _, ext := range staticAssetExtensions {
		if bytes.HasPrefix(rest, []byte(ext)) {
			return true
		}
	}
	return false
}

// mimeTypeRE matches MIME/media-type strings (`application/x-www-form-
// urlencoded`, `multipart/form-data`, `text/plain`) — exactly one slash,
// lowercase registry-style tokens on both sides, no uppercase. These show
// up constantly in HTTP client code/docs (axios's README.md and
// docs/*/config-defaults.md fired 5 hits on exactly this string) and sit
// right next to Authorization/token keywords in request-header examples,
// but a real secret is essentially never confined to this all-lowercase,
// single-slash shape.
var mimeTypeRE = regexp.MustCompile(`^[a-z][a-z0-9.+-]*/[a-z0-9.+-]*[a-z][a-z0-9.+-]*$`)

func looksLikeMimeType(s string) bool {
	return mimeTypeRE.MatchString(s)
}

// decodesToPrintableText reports whether s, interpreted as base64 (padded
// out if needed, standard or URL-safe alphabet), decodes cleanly to bytes
// that are all printable ASCII. A handful of doc/test fixtures embed a
// base64-encoded human-readable string as a Basic-Auth or header example —
// axios's tests/browser/basicAuth.browser.test.js uses RFC 7617's
// canonical `QWxhZGRpbjpvcGVuIHNlc2FtZQ==`, which decodes to "Aladdin:open
// sesame". Real random secrets essentially never decode to all-printable
// text purely by chance: independently ~63% per byte, so well under 1e-9
// for a 20+ byte run — this is a one-way filter, not a coin flip.
func decodesToPrintableText(s string) bool {
	padded := s
	if m := len(s) % 4; m != 0 {
		padded += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return false
		}
	}
	if len(decoded) < 8 {
		return false
	}
	for _, b := range decoded {
		if b < 0x20 || b > 0x7e {
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
