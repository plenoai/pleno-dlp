// Package snov detects Snov.io OAuth2 client_id + client_secret pairs near
// the `snov` keyword. Verified via /v1/oauth/access_token (client_credentials
// grant) on api.snov.io. Raw carries the client_id, RawV2 the secret.
package snov

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.snov.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var idRe = regexp.MustCompile(`\b([a-f0-9]{32,40})\b`)

var contextKeywords = []string{"snov"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Snov }

func (Scanner) Keywords() []string { return []string{"snov"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := idRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var pairs [][2]string
	collected := []string{}
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
		collected = append(collected, token)
	}
	if len(collected) < 2 {
		return nil, nil
	}
	pairs = append(pairs, [2]string{collected[0], collected[1]})
	out := make([]detectors.Result, 0, len(pairs))
	for _, p := range pairs {
		res := detectors.Result{
			DetectorType: detectors.Snov,
			Raw:          []byte(p[0]),
			RawV2:        []byte(p[1]),
			Redacted:     redact(p[0]),
		}
		if verify {
			v, err := s.Verify(ctx, p[0]+":"+p[1])
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	clientID, clientSecret := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v1/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
