// Package clickhousecloud detects ClickHouse Cloud API key + secret pairs.
// ClickHouse Cloud mints two strings together: an access key id (`<32 chars>`)
// and a paired secret (40-80 char base64url). Both shapes collide with hashes /
// generic base64, so co-occurrence with `clickhouse_cloud` / `clickhouse_api` /
// `chc_` keywords in a 256-byte window is mandatory.
//
// Verification is live: ClickHouse Cloud's REST API uses HTTP Basic auth with
// the Key ID as username and the Key Secret as password against the globally
// fixed host https://api.clickhouse.cloud/v1. GET /v1/organizations lists the
// caller's organizations with no org id in the path, so the pair alone is a
// sufficient credential to probe — no per-org host is required.
package clickhousecloud

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.clickhouse.cloud"

var httpClient = &http.Client{Timeout: 10 * time.Second}

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

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
		res := detectors.Result{
			DetectorType: detectors.ClickHouseCloud,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"key_id": id},
		}
		if verify {
			v, err := verifyPair(ctx, id, secret)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify accepts the credential packed as "<keyID>:<keySecret>", matching the
// engine-level pair convention (see datadog / aws).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, sec)
}

// splitPair splits on the FIRST ':' only — the Key Secret is base64url and
// never contains ':' but the Key ID is also ':'-free, so first-colon is safe.
func splitPair(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// verifyPair probes GET /v1/organizations with HTTP Basic auth (Key ID as
// username, Key Secret as password). 200 = valid; 401/403 = rejected; 429 and
// 5xx are surfaced as transient errors via ClassifyVerifyHTTP.
func verifyPair(ctx context.Context, id, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/organizations", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Accept", "application/json")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
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
