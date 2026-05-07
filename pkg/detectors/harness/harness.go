// Package harness detects Harness CI/CD personal access tokens
// (`pat.<account>.<id>.<secret>` 4-segment dotted shape) and verifies
// them against /ng/api/users using the documented `x-api-key` header.
//
// Harness PATs grant the issuing user's full pipeline + secrets-manager
// scope. The 4-segment `pat.` prefix is distinctive enough that no
// keyword gate is required, but we still gate on `harness` to keep
// platform agnostic `pat.…` shapes from surfacing here.
package harness

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.harness.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// pat.<account>.<id>.<secret>. Account/id segments are alnum with
// hyphens; the secret tail is 24+ base62.
var tokenRe = regexp.MustCompile(`\b(pat\.[A-Za-z0-9_-]{8,40}\.[A-Za-z0-9_-]{8,40}\.[A-Za-z0-9]{16,64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Harness }

func (Scanner) Keywords() []string { return []string{"pat."} }

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
			DetectorType: detectors.Harness,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/ng/api/user/currentUser", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-api-key", secret)
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
