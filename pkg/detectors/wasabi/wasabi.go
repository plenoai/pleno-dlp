// Package wasabi detects Wasabi access key + secret pairs (S3-compatible
// shape: 20-char access key, 40-char secret) gated on the `wasabi`
// keyword window. Wasabi is multi-region (us-east-1.wasabisys.com,
// us-west-1, eu-central-1, ap-northeast-1, etc) so verifying requires
// signing a SigV4 request to a region we have to guess — surfaced
// unverified-by-design.
package wasabi

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	accessKeyRe = regexp.MustCompile(`\b([A-Z0-9]{20})\b`)
	secretRe    = regexp.MustCompile(`\b([A-Za-z0-9+/]{40})\b`)
)

var contextKeywords = []string{"wasabi", "wasabi_access_key", "wasabi_secret", "wasabisys"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Wasabi }

func (Scanner) Keywords() []string { return []string{"wasabi"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	keys := accessKeyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		key := string(data[k[2]:k[3]])
		// Skip AKIA/ASIA prefixes — those are real AWS, not Wasabi.
		if strings.HasPrefix(key, "AKIA") || strings.HasPrefix(key, "ASIA") {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret, ok := nearestSecret(k[2], data, secrets, key)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Wasabi,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"access_key_id": key},
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestSecret(keyStart int, data []byte, hits [][]int, key string) (string, bool) {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		if s == key {
			continue
		}
		dist := h[2] - keyStart
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = s
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
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
