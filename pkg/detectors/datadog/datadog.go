// Package datadog detects Datadog API keys (32 hex) optionally paired with
// Application keys (40 hex), and verifies them via /api/v1/validate.
package datadog

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.datadoghq.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// API key: 32 lowercase hex chars. Application key: 40 hex chars.
var (
	apiRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
	appRe = regexp.MustCompile(`\b([a-fA-F0-9]{40})\b`)
)

// Datadog candidates are extremely common shapes (md5, sha1) so the keyword
// gate is essential — only chunks that mention "datadog" or DD_ envs reach us.
type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Datadog }

func (Scanner) Keywords() []string {
	return []string{"datadog", "DD_API_KEY", "DD_APP_KEY", "DD_APPLICATION_KEY"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	apiHits := apiRe.FindAllSubmatchIndex(data, -1)
	if len(apiHits) == 0 {
		return nil, nil
	}
	appHits := appRe.FindAllSubmatchIndex(data, -1)

	out := make([]detectors.Result, 0, len(apiHits))
	seen := map[string]struct{}{}
	for _, m := range apiHits {
		api := string(data[m[2]:m[3]])
		if _, dup := seen[api]; dup {
			continue
		}
		seen[api] = struct{}{}
		app, ok := nearestApp(m[2], data, appHits)
		res := detectors.Result{
			DetectorType: detectors.Datadog,
			Raw:          []byte(api),
			Redacted:     redact(api),
		}
		if ok {
			res.RawV2 = []byte(app)
			if verify {
				v, err := verifyPair(ctx, api, app)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		// Single-key (no app) candidates are emitted unverified so operators
		// see the surface area; they can pair manually if they have the app key.
		out = append(out, res)
	}
	return out, nil
}

// nearestApp picks the closest 40-hex match within 256 bytes of the api-key
// position. Same shape as the AWS detector's nearestSecret.
func nearestApp(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	// secret is expected as "<api>:<app>"; engine-level verify path packs
	// pairs the same way as AWS.
	api, app, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, api, app)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, api, app string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("DD-API-KEY", api)
	req.Header.Set("DD-APPLICATION-KEY", app)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
