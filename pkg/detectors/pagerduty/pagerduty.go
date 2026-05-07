// Package pagerduty detects PagerDuty REST API tokens (20-char alnum) and
// verifies them against /users.
//
// PagerDuty's token shape is a generic 20 characters from [A-Za-z0-9_-], which
// would explode with false positives if scanned blindly. We require a
// co-occurring "pagerduty" / "PD_API_KEY" keyword in the surrounding 256-byte
// window — same gating model as the cloudflare detector.
package pagerduty

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.pagerduty.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{20})\b`)

var contextKeywords = []string{"pagerduty", "pd_api_key", "pd_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PagerDuty }

func (Scanner) Keywords() []string { return []string{"pagerduty", "PD_API_KEY", "PD_TOKEN"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}

	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Mandatory co-occurrence — without a keyword in the window, every
		// 20-char base64-ish chunk would surface.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.PagerDuty,
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
	return out, nil
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/users", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token token="+secret)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")

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
