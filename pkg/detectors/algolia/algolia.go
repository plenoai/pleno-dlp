// Package algolia detects Algolia admin API keys (32 lowercase hex) and
// optionally pairs them with the application id when one is in scope.
//
// Verify is conditional. Algolia's admin endpoint lives at
// `https://<app-id>-dsn.algolia.net/1/indexes` — we can verify only when the
// 10-char application id is present in the same chunk. Lone keys surface as
// unverified-by-design (any 32-hex string is too generic to probe blind).
package algolia

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBaseTemplate has %s replaced by the Algolia application id. Tests
// override the template wholesale to point at httptest.
var apiBaseTemplate = "https://%s-dsn.algolia.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// 32 lowercase hex.
	keyRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
	// Algolia application ids are documented as 10 uppercase alphanumerics.
	appIDRe = regexp.MustCompile(`\b([A-Z0-9]{10})\b`)
)

var contextKeywords = []string{"algolia", "algolia_api_key", "algolia_admin_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Algolia }

func (Scanner) Keywords() []string { return []string{"algolia"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	apps := appIDRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Algolia,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if app, ok := nearestAppID(h[2], data, apps); ok {
			res.RawV2 = []byte(app)
			res.ExtraData = map[string]string{"application_id": app}
			if verify {
				v, err := verifyPair(ctx, app, token)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func nearestAppID(start int, data []byte, apps [][]int) (string, bool) {
	const maxDistance = 512
	bestDist := maxDistance + 1
	best := ""
	for _, a := range apps {
		s, e := a[2], a[3]
		dist := abs(s - start)
		if dist < bestDist {
			bestDist = dist
			best = string(data[s:e])
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	app, key, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, app, key)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, app, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := strings.Replace(apiBaseTemplate, "%s", app, 1) + "/1/indexes"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Algolia-Application-Id", app)
	req.Header.Set("X-Algolia-API-Key", key)

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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
