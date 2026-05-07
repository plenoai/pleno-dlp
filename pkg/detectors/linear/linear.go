// Package linear detects Linear personal API keys (lin_api_<40>) and
// verifies them against the GraphQL endpoint.
//
// Quirk: Linear takes the raw token as the Authorization header value with
// no "Bearer " prefix. This is unusual; getting it wrong returns 200 with
// a GraphQL-level error in the body, which would falsely surface as
// verified.
package linear

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.linear.app"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(lin_api_[A-Za-z0-9]{40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Linear }

func (Scanner) Keywords() []string { return []string{"lin_api_"} }

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
			DetectorType: detectors.Linear,
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

	body := strings.NewReader(`{"query":"{ viewer { id } }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/graphql", body)
	if err != nil {
		return false, err
	}
	// Linear takes the raw token, NOT "Bearer ...". See package doc.
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")

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
	// Keep "lin_api_" + 4 chars after = 12 chars.
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
