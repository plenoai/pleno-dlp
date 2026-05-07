// Package anthropicadmin detects Anthropic Console admin API keys
// (`sk-ant-admin-...`) which are distinct from runtime API keys
// (`sk-ant-api03-...`). Admin keys grant Console-scope access — billing,
// workspace membership, key rotation — so they surface SeverityCritical.
//
// Verification calls /v1/organizations/me, the documented admin-scoped
// endpoint, with the same `x-api-key` + `anthropic-version` headers used
// by the runtime API. A 200 confirms the key is admin-scoped and active.
package anthropicadmin

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.anthropic.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sk-ant-admin- + 20+ base62/_-/.. The pkg/detectors/anthropic package
// owns sk-ant- generally; we own only the admin- subset.
var keyRe = regexp.MustCompile(`\b(sk-ant-admin-[A-Za-z0-9_-]{20,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AnthropicAdmin }

func (Scanner) Keywords() []string { return []string{"sk-ant-admin-"} }

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
			DetectorType: detectors.AnthropicAdmin,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Admin keys revoke/rotate every credential on the org;
			// surface SeverityCritical even unverified.
			Severity: detectors.SeverityCritical,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/organizations/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

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
	if len(t) <= 13 {
		return t
	}
	return t[:13] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
