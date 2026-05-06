// Package github detects GitHub Personal Access Tokens (classic and
// fine-grained) and verifies them against api.github.com/user.
package github

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is overridable from tests so verification can hit an httptest server.
var apiBase = "https://api.github.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Classic PAT: ghp_ + 36 base62 chars.
// Fine-grained PAT: github_pat_ + 82 chars from [A-Za-z0-9_].
var (
	classicRe = regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36})\b`)
	fineRe    = regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitHub }

func (Scanner) Keywords() []string { return []string{"ghp_", "github_pat_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := classicRe.FindAll(data, -1)
	matches = append(matches, fineRe.FindAll(data, -1)...)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.GitHub,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusTooManyRequests:
		// Treat rate-limit as unverified rather than blocking the scan.
		return false, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
