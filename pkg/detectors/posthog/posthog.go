// Package posthog detects PostHog personal API keys (`phx_<base62>`).
//
// PostHog's `phc_` (project) keys are publishable — they appear in
// browser bundles by design — so we only emit `phx_` personal keys
// here. Personal keys grant full account scope (read all projects, write
// dashboards, manage org membership), so they surface SeverityHigh by
// default and SeverityCritical when verified.
//
// Verification calls /api/projects/@current with Bearer auth.
package posthog

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.posthog.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// phx_ + 40+ base62 chars. Production personal keys are 43 chars total.
var keyRe = regexp.MustCompile(`\b(phx_[A-Za-z0-9]{40,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PostHog }

func (Scanner) Keywords() []string { return []string{"phx_"} }

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
			DetectorType: detectors.PostHog,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/projects/@current", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
