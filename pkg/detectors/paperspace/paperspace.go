// Package paperspace detects Paperspace API keys and verifies them via
// /users/getPublicProfile. Paperspace tokens look like base64url runs of
// 40+ chars that frequently appear next to a `paperspace` keyword in
// shell exports / CI vars.
package paperspace

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.paperspace.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 40-char base64url. Optional `api_` documentation prefix is captured
// via an alternation rather than hard-required because production keys
// often don't carry the prefix in the raw value.
var keyRe = regexp.MustCompile(`\b((?:api_)?[A-Za-z0-9_-]{40})\b`)

var contextKeywords = []string{"paperspace", "paperspace_api", "paperspace_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Paperspace }

func (Scanner) Keywords() []string { return []string{"paperspace"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAllSubmatchIndex(data, -1)
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
			DetectorType: detectors.Paperspace,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/users/getPublicProfile", nil)
	if err != nil {
		return false, err
	}
	// Paperspace accepts X-Api-Key as well; Bearer is the documented
	// public form and matches their gradient-cli behavior.
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Api-Key", secret)

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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
