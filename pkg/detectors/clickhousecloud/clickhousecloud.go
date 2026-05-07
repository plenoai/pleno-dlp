// Package clickhousecloud detects ClickHouse Cloud API key + secret pairs.
// ClickHouse Cloud mints two strings together: an access key (`<32-hex>` /
// `KEY-…`) and a paired secret (40+ char base64url). Both shapes collide
// with hashes / generic base64, so co-occurrence with `clickhouse_cloud` /
// `clickhouse_api` / `chc_` keywords in a 256-byte window is mandatory.
//
// Verification is unverified-by-design: ClickHouse Cloud's REST API requires
// the per-organization host (https://api.clickhouse.cloud/v1/organizations/
// <org-id>/...) which is not present in the chunk.
package clickhousecloud

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	idRe     = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,80})\b`)
)

var contextKeywords = []string{
	"clickhouse_cloud",
	"clickhouse_api",
	"chc_",
	"clickhouse.cloud",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ClickHouseCloud }

func (Scanner) Keywords() []string {
	return []string{"clickhouse_cloud", "clickhouse.cloud"}
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
		secret, ok := nearestSecret(k[2], data, secrets, id)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.ClickHouseCloud,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"key_id": id},
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestSecret(idStart int, data []byte, hits [][]int, idValue string) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		candidate := string(data[h[2]:h[3]])
		if candidate == idValue {
			continue
		}
		dist := abs(h[2] - idStart)
		if dist < bestDist {
			bestDist = dist
			best = candidate
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
