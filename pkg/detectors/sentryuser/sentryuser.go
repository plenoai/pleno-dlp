// Package sentryuser detects Sentry user auth tokens (`sntryu_<hex>`),
// distinct from the project DSNs handled by pkg/detectors/sentry. User
// tokens carry the issuing user's full org-membership scope and are
// rotation-painful, so they surface SeverityHigh by default.
//
// Verification calls /api/0/ with Bearer auth — the documented liveness
// endpoint that returns 200 for any valid token regardless of scope.
package sentryuser

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://sentry.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sntryu_ + 64 lowercase hex.
var keyRe = regexp.MustCompile(`\b(sntryu_[a-f0-9]{64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SentryUser }

func (Scanner) Keywords() []string { return []string{"sntryu_"} }

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
			DetectorType: detectors.SentryUser,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/0/", nil)
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
	if len(t) <= 9 {
		return t
	}
	return t[:9] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
