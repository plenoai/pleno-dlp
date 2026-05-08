// Package ortto detects Ortto (formerly Autopilot) marketing-automation
// API keys (`pak_` prefix + 32-64 alnum) near the `ortto` /
// `autopilothq` keyword. Verified via /v1/person/get on api.ap3api.com
// with an X-Api-Key header (Ortto's standard auth header).
package ortto

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.ap3api.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Ortto/Autopilot personal access keys: `pak_` + 32-64 alnum chars.
var tokenRe = regexp.MustCompile(`\b(pak_[A-Za-z0-9]{32,64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Ortto }

func (Scanner) Keywords() []string { return []string{"pak_"} }

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
		// Disambiguate from other `pak_` issuers by requiring an Ortto
		// or Autopilot keyword nearby.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Ortto,
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
	for _, kw := range []string{"ortto", "autopilothq", "ap3api"} {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v1/person/get", strings.NewReader(`{}`))
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Content-Type", "application/json")
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
