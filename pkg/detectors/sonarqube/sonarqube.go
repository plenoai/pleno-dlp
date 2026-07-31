// Package sonarqube detects SonarQube / SonarCloud user tokens. Modern
// tokens are prefixed `sqp_` (project), `squ_` (user), `sqa_` (analysis),
// or `sonar` followed by 40-char hex. Both SonarCloud (sonarcloud.io) and
// self-hosted SonarQube share the same token shape. SonarCloud variant is
// verified via /api/authentication/validate with HTTP Basic auth (token as
// username, blank password) — read-only and confirms tenant scope.
package sonarqube

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://sonarcloud.io"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

const maxVerifyResponseBytes = 1 << 20

var (
	prefixedRe = regexp.MustCompile(`\b(sq[apu]_[A-Za-z0-9]{40})\b`)
	legacyRe   = regexp.MustCompile(`\b([a-f0-9]{40})\b`)
)

var contextKeywords = []string{"sonar", "sonarqube", "sonarcloud", "sonar_token", "sonar_login"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SonarQube }

func (Scanner) Keywords() []string { return []string{"sonar"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}

	for _, h := range prefixedRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, s.build(ctx, token, verify))
	}
	for _, h := range legacyRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// legacy 40-hex shape: must be near a sonar keyword
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, s.build(ctx, token, verify))
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s Scanner) build(ctx context.Context, token string, verify bool) detectors.Result {
	res := detectors.Result{
		DetectorType: detectors.SonarQube,
		Raw:          []byte(token),
		Redacted:     redact(token),
	}
	if verify {
		v, err := s.Verify(ctx, token)
		res.Verified = v
		res.VerificationErr = err
	}
	return res
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/authentication/validate", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	accepted, err := detectors.ClassifyVerifyHTTP(
		resp,
		err,
		[]int{http.StatusOK},
		[]int{http.StatusUnauthorized, http.StatusForbidden},
	)
	if err != nil || !accepted {
		return false, err
	}

	var result struct {
		Valid *bool `json:"valid"`
	}
	if err := detectors.DecodeVerifyJSON(resp.Body, maxVerifyResponseBytes, &result); err != nil {
		return false, fmt.Errorf("verify: decode SonarQube validation response: %w", err)
	}
	if result.Valid == nil {
		return false, fmt.Errorf("verify: SonarQube validation response is missing valid")
	}
	return *result.Valid, nil
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
