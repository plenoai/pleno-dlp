// Package closecrm detects Close.com API keys — `api_<base62>` strings near
// the `close` / `closecrm` keyword. Verified via /api/v1/me/ on
// api.close.com using HTTP basic auth (api key as username, empty password).
package closecrm

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.close.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// Close API keys are documented as `api_<base62>{40,}` (the `api_` prefix
// is consistent across the platform).
var tokenRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`\b(api_[A-Za-z0-9]{40,80})\b`) })

var contextKeywords = []string{"close.com", "closecrm", "close_api", "close_crm"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Close }

func (Scanner) Keywords() []string { return []string{"close", "api_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !detectors.HasWordRunCandidate(data, "api_", len("api_")+40) {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	if !hasContextKeyword(lower) {
		return nil, nil
	}
	hits := tokenRe().FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
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
			DetectorType: detectors.Close,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
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

func hasContextKeyword(lower string) bool {
	for _, kw := range contextKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/me/", nil)
	if err != nil {
		return false, err
	}
	// Close.com uses HTTP basic with api key as user, empty password.
	auth := base64.StdEncoding.EncodeToString([]byte(secret + ":"))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

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
