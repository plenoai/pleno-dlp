// Package onelogin detects OneLogin API client secrets (64-hex co-occurring
// with `onelogin`) and verifies them against the /api/2/users endpoint using
// the documented `Authorization: bearer:<token>` header form.
//
// OneLogin client_secret values come from API credentials configured in the
// OneLogin admin console. Leaks grant directory-admin scope per the role the
// credential is assigned to. The 64-hex shape collides with SHA-256 digests,
// so a co-occurring `onelogin` keyword in a 256-byte window is mandatory.
package onelogin

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.us.onelogin.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

var contextKeywords = []string{"onelogin", "onelogin_secret", "onelogin_client", "onelogin.com"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OneLogin }

func (Scanner) Keywords() []string { return []string{"onelogin"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.OneLogin,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/2/users?limit=1", nil)
	if err != nil {
		return false, err
	}
	// OneLogin uses `bearer:<token>` (lowercase, colon) per the documented
	// API-credential form. The capitalized RFC `Bearer ` form is rejected.
	req.Header.Set("Authorization", "bearer:"+secret)
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
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
