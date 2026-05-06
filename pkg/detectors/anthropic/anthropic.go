// Package anthropic detects Anthropic API keys (sk-ant-…) and verifies them
// with a 1-token /v1/messages probe.
package anthropic

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.anthropic.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{20,})\b`)

// probeBody is the smallest legal /v1/messages request — 1 max token, single
// user turn. Sufficient to distinguish 401/403 (bad key) from 200 (valid).
var probeBody = []byte(`{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Anthropic }

func (Scanner) Keywords() []string { return []string{"sk-ant-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.Anthropic,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v1/messages", bytes.NewReader(probeBody))
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	case http.StatusTooManyRequests:
		return false, nil
	default:
		// Other errors (e.g. 400 due to model mismatch) shouldn't classify as
		// verified, but they also imply the key was authenticated. Stay strict
		// and only return true on 200 to avoid false positives.
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 7 {
		return t
	}
	return t[:7] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
