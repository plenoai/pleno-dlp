// Package backblazeb2 detects Backblaze B2 application key id + key pair.
// Application key IDs are 25-char base64-ish strings prefixed with "K00";
// the application key itself is 31 chars typically with prefix "K00" as
// well. The pair is used with b2_authorize_account, but the regional API
// host (api.backblazeb2.com) returns a session token rather than a yes/no
// — and an unsuccessful auth could indicate either bad credentials or a
// network issue. We surface the pair unverified-by-design and let the
// operator rotate. Co-occurrence with `b2_` / `backblaze` keyword is
// mandatory.
package backblazeb2

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	keyIDRe = regexp.MustCompile(`\b(K00[A-Za-z0-9]{22,30})\b`)
	keyRe   = regexp.MustCompile(`\b(K00[A-Za-z0-9+/]{28,60})\b`)
)

var contextKeywords = []string{"b2_", "backblaze", "b2_application_key", "b2_app_key", "b2_key_id"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BackblazeB2 }

func (Scanner) Keywords() []string { return []string{"b2_", "backblaze"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	ids := keyIDRe.FindAllSubmatchIndex(data, -1)
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(ids) == 0 || len(keys) == 0 {
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
		key, ok := nearestKey(k[2], data, keys, id)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.BackblazeB2,
			Raw:          []byte(id),
			RawV2:        []byte(key),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"key_id": id},
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestKey(idStart int, data []byte, hits [][]int, id string) (string, bool) {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		// Application key proper is longer than the key id, and never the
		// same string; skip the id match itself when iterating.
		if s == id || len(s) <= len(id) {
			continue
		}
		dist := h[2] - idStart
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
