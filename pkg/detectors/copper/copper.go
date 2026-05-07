// Package copper detects Copper CRM credentials — user_email +
// access_token pair near the `copper` keyword. Verified via
// /developer_api/v1/account on api.copper.com using X-PW-AccessToken,
// X-PW-Application, and X-PW-UserEmail headers. Raw carries the email,
// RawV2 the token.
package copper

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.copper.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

var contextKeywords = []string{"copper"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Copper }

func (Scanner) Keywords() []string { return []string{"copper"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	emails := emailRe.FindAllSubmatchIndex(data, -1)
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(emails) == 0 || len(tokens) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var email string
	for _, h := range emails {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		email = string(data[h[2]:h[3]])
		break
	}
	if email == "" {
		return nil, nil
	}
	var token string
	for _, h := range tokens {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == email {
			continue
		}
		token = v
		break
	}
	if token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Copper,
		Raw:          []byte(email),
		RawV2:        []byte(token),
		Redacted:     redact(email),
	}
	if verify {
		v, err := s.Verify(ctx, email+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	email, token := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/developer_api/v1/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-PW-AccessToken", token)
	req.Header.Set("X-PW-Application", "developer_api")
	req.Header.Set("X-PW-UserEmail", email)
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
