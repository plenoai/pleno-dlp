// Package anthropic detects Anthropic API keys (sk-ant-api03-...) and verifies
// them with the read-only /v1/models endpoint.
package anthropic

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.anthropic.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

const maxVerifyResponseBytes = 64 << 10

var keyRe = regexp.MustCompile(`\b(sk-ant-api03-[A-Za-z0-9_-]{93}AA)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Anthropic }

func (Scanner) Keywords() []string { return []string{"sk-ant-api03-"} }

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

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(apiBase, "/")+"/v1/models",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("accept", "application/json")

	resp, err := httpClient.Do(req)
	accepted, classifyErr := detectors.ClassifyVerifyHTTP(
		resp,
		err,
		[]int{http.StatusOK},
		[]int{http.StatusUnauthorized, http.StatusNotFound},
	)
	if resp == nil {
		return accepted, classifyErr
	}
	defer resp.Body.Close()
	if _, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxVerifyResponseBytes)); drainErr != nil {
		return false, fmt.Errorf("anthropic verify: read response: %w", drainErr)
	}
	return accepted, classifyErr
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
