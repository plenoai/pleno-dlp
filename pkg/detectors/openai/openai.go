// Package openai detects OpenAI API keys (sk-…, sk-proj-…) and verifies them
// against the /v1/models endpoint. Anthropic keys (sk-ant-…) share the "sk-"
// prefix and must be excluded — that responsibility lives in the regex below.
package openai

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-secret-scanner/pkg/detectors"
)

var apiBase = "https://api.openai.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Excludes sk-ant- via a negative-lookahead-equivalent: we match `sk-` then
// either `proj-` or any non-`a` char (or `a` not followed by `nt-`). Since Go
// regexp lacks lookaheads, we match broadly and filter in code.
var keyRe = regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OpenAI }

// "sk-" alone would also catch Anthropic keys, but the engine's keyword filter
// is tolerant; the FromData regex + filter step does the discrimination.
func (Scanner) Keywords() []string { return []string{"sk-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		// Hard exclude Anthropic — same prefix, different provider.
		if strings.HasPrefix(token, "sk-ant-") {
			continue
		}
		res := detectors.Result{
			DetectorType: detectors.OpenAI,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/models", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return false, nil
	}
	return resp.StatusCode == http.StatusOK, nil
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
