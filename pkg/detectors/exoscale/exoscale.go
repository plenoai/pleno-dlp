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

// Secret is 40+ char base64url (URL-safe alphabet, may include `-` and `_`).
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,128})\b`)

var contextKeywords = []string{"exoscale", "exo_secret", "exoscale_secret"}

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
		if !nearKeyword(lower, kh[2], kh[3]) {
			continue
		}
		secret := nearestSecret(data, kh[2], kh[3], key)
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

// nearestSecret returns the first secret-shaped token within ±512 bytes of
// the access-key window. The Exoscale key prefix is excluded so the key
// itself can't be paired with itself.
func nearestSecret(data []byte, start, end int, key string) string {
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
		cand := string(data[from+sh[2] : from+sh[3]])
		if cand == key {
			continue
		}
		if strings.HasPrefix(cand, "EXO") {
			continue
		}
		return cand
	}
	return ""
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
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
