// Package bandwidth detects Bandwidth.com API credentials — a paired
// username + password (each 10+ alphanumeric) near the `bandwidth` keyword.
// Verified via /api/accounts on dashboard.bandwidth.com using HTTP Basic auth.
// Raw carries the username, RawV2 carries the password.
package bandwidth

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://dashboard.bandwidth.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{10,32})\b`)

var contextKeywords = []string{"bandwidth"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bandwidth }

func (Scanner) Keywords() []string { return []string{"bandwidth"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		user := string(data[h[2]:h[3]])
		if _, dup := seen[user]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		var pass string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand != user && nearKeyword(lower, h2[2], h2[3]) {
				pass = cand
				break
			}
		}
		if pass == "" {
			continue
		}
		seen[user] = struct{}{}
		seen[pass] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Bandwidth,
			Raw:          []byte(user),
			RawV2:        []byte(pass),
			Redacted:     redact(user),
		}
		if verify {
			v, err := s.Verify(ctx, user+":"+pass)
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	user, pass := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)
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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
