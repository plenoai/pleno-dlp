// Package emailjs detects EmailJS user_id + private access_token pairs near
// the `emailjs` keyword. The user_id is a short alphanumeric (typically 17
// chars), the access_token is 32+ alnum. Verified via /api/v1.0/account on
// api.emailjs.com with Bearer auth (access_token). Raw carries the user_id,
// RawV2 carries the access_token.
package emailjs

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.emailjs.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var userRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{16,24})\b`)
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{32,64})\b`)

var contextKeywords = []string{"emailjs"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.EmailJS }

func (Scanner) Keywords() []string { return []string{"emailjs"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	users := userRe.FindAllSubmatchIndex(data, -1)
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(users) == 0 || len(tokens) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var user, token string
	for _, h := range users {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		// userRe is permissive — gate length at <=24 to avoid grabbing
		// the long token first.
		if len(v) > 24 {
			continue
		}
		user = v
		break
	}
	if user == "" {
		return nil, nil
	}
	for _, h := range tokens {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == user {
			continue
		}
		token = v
		break
	}
	if token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.EmailJS,
		Raw:          []byte(user),
		RawV2:        []byte(token),
		Redacted:     redact(user),
	}
	if verify {
		v, err := s.Verify(ctx, user+":"+token)
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
	token := parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1.0/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
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
