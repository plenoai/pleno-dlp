// Package auditboard detects AuditBoard GRC API tokens. Tokens are
// alphanumeric and surface only when the `auditboard` keyword is in the
// same chunk. Verified via /api/v1/me on app.auditboard.com with the
// Authorization Bearer header.
package auditboard

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.auditboard.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

var contextKeywords = []string{"auditboard"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AuditBoard }

func (Scanner) Keywords() []string { return []string{"auditboard"} }

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
			DetectorType: detectors.AuditBoard,
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
	const radius = 128
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
