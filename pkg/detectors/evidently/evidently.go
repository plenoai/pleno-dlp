// Package evidently detects Evidently AI / Evidently Cloud API tokens
// (URL-safe base64, 32-80 chars). Surface only when an `evidently`
// keyword is in the same chunk. Verified via /api/v2/auth/profile on
// app.evidently.cloud with the X-Evidently-Token header.
package evidently

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.evidently.cloud"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(dG[A-Za-z0-9_\-]{30,80})\b|\b([A-Za-z0-9_\-]{40,80})\b`)

var contextKeywords = []string{"evidently"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Evidently }

func (Scanner) Keywords() []string { return []string{"evidently"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		var token string
		if h[2] >= 0 {
			token = string(data[h[2]:h[3]])
		} else if h[4] >= 0 {
			token = string(data[h[4]:h[5]])
		} else {
			continue
		}
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Evidently,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/auth/profile", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Evidently-Token", secret)
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
