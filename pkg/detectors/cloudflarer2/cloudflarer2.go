// Package cloudflarer2 detects Cloudflare R2 access keys (access-key-id +
// secret-access-key pair, S3-compatible). The id is 32 lowercase hex and
// the secret is 64 lowercase hex — both shapes collide with sha-something
// digests, so co-occurrence with `r2_access_key` / `cloudflare_r2` /
// `R2_ACCESS_KEY_ID` near the access-key-id is mandatory.
//
// We capture the access key id as Raw and the secret access key as RawV2
// to match the AWS pair convention. R2 tokens grant the issuing account's
// full bucket-level scope (read, write, delete), so verified hits surface
// SeverityCritical.
//
// Verification is left unimplemented (class=b, unverified-by-design) for
// two independent reasons:
//
//  1. The signing host is https://<accountid>.r2.cloudflarestorage.com.
//     The Cloudflare account ID is required to form it; it is NOT the
//     access-key-id, is NOT in RawV2, and the detector captures no
//     endpoint from the chunk. The S3 siblings Wasabi and BackblazeB2
//     are class=b for exactly this region+endpoint-pairing reason.
//  2. R2 uses S3 SigV4 (HMAC-SHA256) signing; proving the secret valid
//     requires computing a real canonical-request signature against that
//     (unavailable) host. A bearer-style probe without a real signature
//     would yield false Verified=true against a live endpoint.
//
// Because both token shapes are pure hex of MD5 (32) / SHA-1 (40 — not
// matched) / SHA-256 (64) digest lengths, the detector applies three
// false-positive gates beyond the keyword requirement:
//   - a Shannon-entropy floor (drops all-zero / sequential placeholders),
//   - a tight vicinity window anchored on the access-key-id,
//   - negative-lookalike exclusion of digest/hash context tokens
//     (sha1, sha256, md5, etag, integrity, checksum, commit, blob, oid,
//     gitref) and rejection of concatenation artifacts (a 64-hex run
//     immediately adjacent to another hex run).
package cloudflarer2

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	idRe     = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
	secretRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)
)

// minHexEntropy is the Shannon-entropy floor (bits/char) for both the
// id and the secret. A hex alphabet has a 4.0-bit ceiling; 3.2 drops
// low-variance/repeated-pattern hex such as all-zero, "deadbeef…"
// repeats, and short sequential placeholders while keeping real
// 16-symbol-balanced credential material.
const minHexEntropy = 3.2

var contextKeywords = []string{
	"r2_access_key",
	"cloudflare_r2",
	"r2_secret",
	"r2_access",
	"r2_endpoint",
	"cloudflarestorage",
}

// digestContextWords are token/key-name fragments that dominate the 32/64-hex
// false-positive population: git refs, content hashes, lockfile integrity
// digests, ETags. If any appears immediately around the candidate id we
// treat the hex as a digest, not an R2 credential.
var digestContextWords = []string{
	"sha1", "sha256", "sha512", "sha384", "md5",
	"etag", "integrity", "checksum", "commit",
	"blob", "oid", "gitref", "digest", "hash",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CloudflareR2 }

func (Scanner) Keywords() []string {
	return []string{"r2_access_key", "cloudflare_r2", "cloudflarestorage"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	ids := idRe.FindAllSubmatchIndex(data, -1)
	if len(ids) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, k := range ids {
		idStart, idEnd := k[2], k[3]
		id := string(data[idStart:idEnd])
		if _, dup := seen[id]; dup {
			continue
		}
		// Entropy floor: drop sequential / repeated placeholder hex.
		if !detectors.HasMinEntropy(id, minHexEntropy) {
			continue
		}
		// Required keyword must sit in a tight window around the id itself,
		// not merely somewhere within a wide co-location radius.
		if !nearKeyword(lower, idStart, idEnd) {
			continue
		}
		// Reject when the id is surrounded by digest/hash context.
		if hasDigestContext(lower, idStart, idEnd) {
			continue
		}
		secret, ok := nearestSecret(idStart, data, secrets)
		if !ok {
			continue
		}
		if !detectors.HasMinEntropy(secret, minHexEntropy) {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.CloudflareR2,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
			// R2 keys move data — surface SeverityCritical even without verify.
			Severity: detectors.SeverityCritical,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearestSecret picks the closest 64-hex match within maxDistance bytes of
// the access-key-id, rejecting candidates that are concatenation artifacts
// (a 64-hex run immediately abutted by another hex digit, i.e. two adjacent
// 32-hex ids glued together) — \b on the regex already blocks an adjacent
// hex char, but we additionally require the match to be entropy-clean.
func nearestSecret(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		// Concatenation guard: \b already prevents an adjacent hex char,
		// but reject if the surrounding non-word boundary still glues two
		// hex runs (e.g. separated only by a non-hex word char is fine;
		// directly adjacent hex is impossible past \b).
		if isConcatArtifact(data, start, end) {
			continue
		}
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// isConcatArtifact reports whether the 64-hex run at [start,end) is directly
// preceded or followed by another hex character. The \b anchors should make
// this impossible for a clean match, but defensive: a 96/128-hex blob would
// be tokenised as one run, never reaching here; this catches the edge where
// surrounding bytes are themselves hex (belt-and-suspenders on the boundary).
func isConcatArtifact(data []byte, start, end int) bool {
	if start > 0 && isHexByte(data[start-1]) {
		return true
	}
	if end < len(data) && isHexByte(data[end]) {
		return true
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// nearKeyword requires an R2 context keyword within a tight window of the
// access-key-id. 96 bytes comfortably covers `R2_ACCESS_KEY_ID=<32hex>`
// shaped env/config lines while excluding coincidental co-location with an
// unrelated digest elsewhere in a wide 256-byte span.
func nearKeyword(lower string, start, end int) bool {
	const radius = 96
	window := windowOf(lower, start, end, radius)
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// hasDigestContext reports whether digest/hash naming sits in the immediate
// vicinity of the candidate id — the dominant 32/64-hex false source.
func hasDigestContext(lower string, start, end int) bool {
	const radius = 64
	window := windowOf(lower, start, end, radius)
	for _, w := range digestContextWords {
		if strings.Contains(window, w) {
			return true
		}
	}
	return false
}

func windowOf(s string, start, end, radius int) string {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(s) {
		to = len(s)
	}
	return s[from:to]
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
