// Package postman detects Postman API keys (PMAK-...) and verifies them
// against /me.
package postman

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.getpostman.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// PMAK- prefix + 24 hex + dash + 34 hex.
var tokenRe = regexp.MustCompile(`\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Postman }

func (Scanner) Keywords() []string { return []string{"PMAK-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Postman,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/me", nil)
	if err != nil {
		return false, err
	}
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

func redact(t string) string {
	// Keep "PMAK-" + 4 chars after = 9 chars.
	if len(t) <= 9 {
		return t
	}
	return t[:9] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
