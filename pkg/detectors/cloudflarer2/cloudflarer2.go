// Package cloudflarer2 detects Cloudflare R2 access keys (access-key-id +
// secret-access-key pair, S3-compatible). The id is 32 lowercase hex and
// the secret is 64 lowercase hex — both shapes collide with sha-something
// digests, so co-occurrence with `r2_access_key` / `cloudflare_r2` /
// `R2_ACCESS_KEY_ID` in a 256-byte window is mandatory.
//
// We capture the access key id as Raw and the secret access key as RawV2
// to match the AWS pair convention. R2 tokens grant the issuing account's
// full bucket-level scope (read, write, delete), so verified hits surface
// SeverityCritical.
//
// Verification is left unimplemented — R2 uses S3 SigV4 against
// <accountid>.r2.cloudflarestorage.com, and the per-account ID isn't in
// the chunk. The keyword + paired shape is the unverified-by-design path.
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

var contextKeywords = []string{
	"r2_access_key",
	"cloudflare_r2",
	"r2_secret",
	"r2_access",
	"r2_endpoint",
	"cloudflarestorage",
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
		id := string(data[k[2]:k[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret, ok := nearestSecret(k[2], data, secrets)
		if !ok {
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

func nearestSecret(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		dist := abs(h[2] - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[h[2]:h[3]])
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
