// Package generic is the catch-all detector that fires on high-entropy
// strings adjacent to a credential keyword. It exists so unknown providers
// (a company-internal "ACME_API_KEY=…" with a novel shape, a third-party
// SaaS we haven't written a dedicated detector for yet) still surface
// findings — at the cost of a higher false-positive rate than provider-
// specific detectors.
//
// Match contract:
//   - Regex captures runs of 20..128 chars from [A-Za-z0-9+/=_-] (covers
//     base64-ish, hex-ish, and dash-separated UUID-ish shapes).
//   - The captured string must score ≥ 4.0 bits-per-byte Shannon
//     entropy. Empirically this rejects "20 zeros" / "AAAAAAA…" / sha256
//     hashes of zeros while keeping real random tokens.
//   - The captured string must appear within 256 bytes of one of the
//     keywords below. Without this gate the detector would fire on every
//     UUID, commit hash, and base64-encoded image embedded in a chunk.
//
// Severity defaults to Medium (already mapped via
// detectors.DefaultSeverity for this DetectorType) — a generic hit
// without an upstream verifier is informative but not as high-confidence
// as a provider-specific detector.
//
// No Verify is implemented: by definition there's no upstream API to
// confirm against. Operators who trust the hit can rotate; the rest get
// flagged for human review.
package generic

import (
	"context"
	"math"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// secretShape captures the run we'll evaluate. Length 20..128 covers
// every real-world API key shape we know about (AWS=20, GitHub=40,
// Slack=50–80, JWT well over 100). The character class includes
// base64url's `-` / `_` so dash-separated tokens match too. Plain
// hyphen-only words (e.g. "fully-qualified-domain-name") are excluded
// by the entropy gate downstream.
//
// `=` is NOT in the class so we don't accidentally splice `key=secret`
// into a single capture — that would hide the secret behind the
// keyword text and defeat the dedup map. Base64 padding `=` at the
// suffix is therefore stripped, but our redact only shows the prefix
// so the user-visible output is unaffected.
var secretShape = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,128}`)

// keywordRadius bounds the byte distance between a credential keyword
// and the secret string. 256 bytes covers a typical config-line layout
// (`API_KEY = "…"`, multi-line YAML with comments) without inflating to
// "the whole chunk".
const keywordRadius = 256

// minEntropy is the Shannon entropy floor. 4.0 bits-per-byte is the
// classical "looks random" line — uniformly-random alphanumerics score
// 5.95, base64 strings score 5.5–5.9, sha256 hex scores 4.0 exactly,
// and "abc abc abc" scores ~1.6. We want hashes in (they could be
// secrets too) and natural-language tokens out, so 4.0 is the cutoff.
const minEntropy = 4.0

// keywords is the gate: we ONLY emit a finding when one of these
// substrings is within keywordRadius bytes of the captured secret. The
// list is hand-curated from common config patterns and HTTP header
// conventions. Match is case-insensitive (the engine's keyword filter
// already enforces lowercase comparison).
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
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GenericHighEntropy }

// Keywords returns the credential-keyword list so the engine's prefilter
// can skip chunks that mention none of them. Without this prefilter,
// every chunk would pay the regex+entropy cost — a huge tax on real
// scans where most files are plain prose / code without secrets.
func (Scanner) Keywords() []string { return keywords }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	// The engine's keyword filter already proved at least one keyword is
	// present somewhere in the chunk. We still need to compute keyword
	// positions to check the radius gate per-candidate.
	lower := strings.ToLower(string(data))
	keywordSpans := keywordPositions(lower)
	if len(keywordSpans) == 0 {
		return nil, nil // engine filter false positive (case quirk); bail.
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

// keywordPositions returns the start offsets of every keyword hit in
// the lower-cased chunk. Used to gate candidates by proximity. We
// scan once and reuse the slice across all candidates rather than
// re-running each match for every regex hit.
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

// nearKeyword reports whether [secretStart, secretEnd) lies within
// keywordRadius bytes of any keyword span. The check is symmetric —
// the secret can appear before or after the keyword (`API_KEY=foo`
// vs `foo  # API_KEY` both match).
func nearKeyword(secretStart, secretEnd int, keywordStarts []int) bool {
	for _, k := range keywordStarts {
		// Distance is the gap between the closer pair of endpoints.
		switch {
		case k <= secretStart && secretStart-k <= keywordRadius:
			return true
		case k >= secretEnd && k-secretEnd <= keywordRadius:
			return true
		case k > secretStart && k < secretEnd:
			return true // overlap (rare; treat as match).
		}
	}
	return false
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
