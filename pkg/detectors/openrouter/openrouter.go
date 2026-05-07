// Package openrouter detects OpenRouter API keys (`sk-or-v1-…`) and verifies
// them against /api/v1/auth/key.
//
// The `sk-or-v1-` prefix is unique to OpenRouter — distinct from OpenAI's
// `sk-` and Anthropic's `sk-ant-` shapes — so a prefix anchor is sufficient
// without a keyword gate.
package openrouter

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://openrouter.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `sk-or-v1-` then 64 hex chars (the documented payload length).
var keyRe = regexp.MustCompile(`\b(sk-or-v1-[a-f0-9]{64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OpenRouter }

func (Scanner) Keywords() []string { return []string{"sk-or-v1-"} }

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
			DetectorType: detectors.OpenRouter,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/auth/key", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
