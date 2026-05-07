// Package aliyun detects Alibaba Cloud (Aliyun) AccessKey id + secret pairs.
//
// AccessKey ids start with `LTAI` and run 16..24 alphanumerics; the paired
// AccessKey secret is a 30-char base62 token. Together they grant the
// owning RAM user's full configured policy — root accounts especially are
// SeverityCritical when paired.
//
// Verify is intentionally not performed. The natural probe is STS
// GetCallerIdentity, but the API endpoint host is region-bound
// (sts.<region>.aliyuncs.com) and the scanner has no reliable way to pick a
// region without leaking which tenant the credential belongs to. Probing
// also leaves an audit-log trail in the credential owner's account, which we
// won't emit silently. So aliyun surfaces unverified-by-design and the
// engine renders it under --unverified-results.
package aliyun

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// LTAI is the canonical AccessKey id prefix. Aliyun has issued shorter (16
// alnum) and longer (24 alnum) variants depending on issuance year; the
// 16..24 range covers both.
var idRe = regexp.MustCompile(`\b(LTAI[A-Za-z0-9]{12,20})\b`)

// AccessKey secrets are 30 base62 chars. We anchor with non-base62 surround
// so adjacent tokens don't merge into a single capture.
var secretRe = regexp.MustCompile(`[^A-Za-z0-9]([A-Za-z0-9]{30})[^A-Za-z0-9]`)

var contextKeywords = []string{"aliyun", "alibaba", "accesskey", "access_key", "alibabacloud"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AlibabaCloud }

// LTAI is distinctive enough on its own. We also prefilter on `aliyun` so
// secret-only chunks (when only the SecretKey leaks but not the id) don't
// reach FromData — pairing requires both.
func (Scanner) Keywords() []string { return []string{"LTAI", "aliyun", "alibaba"} }

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
		// Co-occurrence is mandatory because LTAI prefixed strings appear in
		// internal docs unrelated to live credentials.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}
		secret, hasSecret := nearestRun(m[2], data, secrets, 256)
		res := detectors.Result{
			DetectorType: detectors.AlibabaCloud,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
		}
		if hasSecret {
			res.RawV2 = []byte(secret)
			// Paired credentials grant full account-scope access — Critical.
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
