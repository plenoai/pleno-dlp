// Package tencentcloud detects Tencent Cloud SecretId + SecretKey pairs.
//
// SecretIds start with `AKID` and are 32 alphanumerics; SecretKeys are 32
// base62 chars. Together they grant the owning CAM principal's full
// configured policy — root keys especially are SeverityCritical when paired.
//
// Verify is intentionally not performed. Tencent Cloud's CAM endpoint is
// region-bound (cam.tencentcloudapi.com is the public router but signing
// requires the region as part of the canonical request) and probing leaves
// an audit-log trail in the credential owner's account. So tencentcloud
// surfaces unverified-by-design and the engine renders it under
// --unverified-results.
package tencentcloud

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// SecretId: `AKID` + 32 alphanumerics. Tencent issues both 32 and 36-char
// variants depending on issuance year; we accept 32..40.
var idRe = regexp.MustCompile(`\b(AKID[A-Za-z0-9]{28,36})\b`)

// SecretKey: 32 base62 chars.
var secretRe = regexp.MustCompile(`[^A-Za-z0-9]([A-Za-z0-9]{32})[^A-Za-z0-9]`)

var contextKeywords = []string{"tencent", "tencentcloud", "secret_id", "secret_key", "tencent_cloud"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TencentCloud }

func (Scanner) Keywords() []string { return []string{"AKID", "tencent"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idMatches))
	seen := map[string]struct{}{}
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		// Co-occurrence is mandatory: AKID-prefixed strings appear in unrelated
		// internal tooling.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}
		secret, hasSecret := nearestRun(m[2], data, secrets, 256)
		res := detectors.Result{
			DetectorType: detectors.TencentCloud,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"secret_id": id},
		}
		if hasSecret {
			res.RawV2 = []byte(secret)
			res.Severity = detectors.SeverityCritical
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestRun(idStart int, data []byte, runs [][]int, maxDistance int) (string, bool) {
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range runs {
		start, end := sm[2], sm[3]
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
