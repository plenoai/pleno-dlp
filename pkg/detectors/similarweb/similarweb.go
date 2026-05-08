// Package similarweb detects SimilarWeb API keys near the `similarweb`
// keyword. Verified via /v1/website/example.com/total-traffic-and-engagement/visits
// on api.similarweb.com with an api_key query parameter.
package similarweb

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.similarweb.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SimilarWeb keys are 32 hex chars (md5-shaped).
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"similarweb", "similar-web", "similar_web"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SimilarWeb }

func (Scanner) Keywords() []string { return []string{"similarweb"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.SimilarWeb,
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
	q := url.Values{
		"api_key":          {secret},
		"start_date":       {"2024-01"},
		"end_date":         {"2024-01"},
		"granularity":      {"monthly"},
		"main_domain_only": {"false"},
	}
	probe := strings.TrimRight(apiBase, "/") + "/v1/website/example.com/total-traffic-and-engagement/visits?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func redact(t string) string {
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
