// Package githubapp detects GitHub Apps installation access tokens
// (`ghs_<base62>{36}`), distinct from PATs (handled by pkg/detectors/github).
//
// Installation tokens expire after 1 hour but, while live, grant the App's
// full permission set on the installed scope. We surface SeverityHigh
// even though they're short-lived because rotation requires regenerating
// the installation token via the App's signed JWT, which is harder than
// a PAT rotation.
package githubapp

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.github.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// ghs_ + 36 base62 chars — same suffix shape as ghp_, distinct prefix.
var keyRe = regexp.MustCompile(`\b(ghs_[A-Za-z0-9]{36})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitHubApp }

func (Scanner) Keywords() []string { return []string{"ghs_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
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
			DetectorType: detectors.GitHubApp,
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

	// /installation/repositories is the canonical installation-token scope
	// probe. It returns 200 only when called with a live ghs_ token.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/installation/repositories", nil)
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
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
