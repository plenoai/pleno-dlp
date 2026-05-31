// Package exoscale detects Exoscale IaaS access-key + secret-key pairs near
// the `exoscale` keyword. The access key is EXO-prefixed; the matching
// secret-key is 40+ char base64url. Both halves must appear in the chunk.
// Raw carries the access key; RawV2 carries the paired secret. Exoscale
// signs requests with HMAC-SHA1 over the query, so verification is
// impractical for a generic detector — unverified by design.
package exoscale

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Exoscale API keys are documented as `EXO<base62>{56}` (uppercase prefix).
var keyRe = regexp.MustCompile(`\b(EXO[A-Za-z0-9]{56})\b`)

// Secret is base64url (URL-safe alphabet, may include `-` and `_`). The
// observed Exoscale secret shape is ~43-44 chars; we cap the upper bound
// at 80 (down from 128) to shed long base64 blobs (PEM bodies, JWTs) that
// a 128-wide window would otherwise swallow.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,80})\b`)

// Negative lookalikes the secret regex would otherwise match:
//   - pure-hex SHA digests (sha1=40, sha256=64) — low information, never
//     an Exoscale secret which uses the full base64url alphabet.
//   - JWT segments — base64url but begin with the fixed `eyJ` header marker.
//   - PEM body lines — base64 starting with the ASN.1 `MII` DER prefix.
var (
	hexRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

const (
	jwtPrefix = "eyJ"
	pemPrefix = "MII"
	// secretMinEntropy gates against low-entropy lookalikes (config nonces
	// of repeated chars, predictable placeholders). Real base64url secrets
	// sit well above 5 bits/char; 4.0 leaves margin while killing the
	// all-zeros / single-char-run shapes.
	secretMinEntropy = 4.0
)

var contextKeywords = []string{"exoscale", "exo_secret", "exoscale_secret"}

// secretVicinity bounds how far the secret token may sit from a context
// keyword. The access key already proves Exoscale relevance; this ensures
// the secret *half* is itself anchored to provider context rather than a
// random co-located blob.
const secretVicinity = 256

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Exoscale }

func (Scanner) Keywords() []string { return []string{"exoscale", "exo"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, kh := range keyHits {
		key := string(data[kh[2]:kh[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeywordWindow(lower, kh[2], kh[3], 256) {
			continue
		}
		secret := nearestSecret(data, lower, kh[2], kh[3], key)
		if secret == "" {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Exoscale,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearestSecret returns the first plausible Exoscale secret within ±512
// bytes of the access-key window. Beyond the shape regex it requires the
// candidate to (1) not be the access key itself, (2) clear a Shannon
// entropy floor, (3) not be a hex digest / JWT / PEM lookalike, and (4)
// sit within secretVicinity bytes of a context keyword — so a long
// base64-ish blob merely co-located with an EXO key is not emitted.
func nearestSecret(data []byte, lower string, start, end int, key string) string {
	const radius = 512
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(data) {
		to = len(data)
	}
	for _, sh := range secretRe.FindAllSubmatchIndex(data[from:to], -1) {
		absStart := from + sh[2]
		absEnd := from + sh[3]
		cand := string(data[absStart:absEnd])
		if cand == key || strings.HasPrefix(cand, "EXO") {
			continue
		}
		if !plausibleSecret(cand) {
			continue
		}
		if !nearKeywordWindow(lower, absStart, absEnd, secretVicinity) {
			continue
		}
		return cand
	}
	return ""
}

// plausibleSecret rejects the false-positive shapes that share the
// base64url alphabet with a real Exoscale secret.
func plausibleSecret(cand string) bool {
	if hexRe.MatchString(cand) {
		return false // sha1/sha256 digest, git object id, etc.
	}
	if strings.HasPrefix(cand, jwtPrefix) {
		return false // JWT header segment
	}
	if strings.HasPrefix(cand, pemPrefix) {
		return false // PEM/DER base64 body line
	}
	if !detectors.HasMinEntropy(cand, secretMinEntropy) {
		return false // repeated-char / placeholder nonce
	}
	return true
}

// nearKeywordWindow reports whether any context keyword appears within
// radius bytes of [start,end).
func nearKeywordWindow(lower string, start, end, radius int) bool {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
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
