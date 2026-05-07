// Package figma detects Figma personal access tokens (`figd_…` legacy /
// `figpat_…` 2024+ format) and verifies them against /v1/me using the
// documented `X-Figma-Token` header.
package figma

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.figma.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `figd_` legacy: ~40 base64url chars; `figpat_` modern: 6-segment dash
// shape ending in 32 base64url. We accept either.
var tokenRe = regexp.MustCompile(`\b(fig(?:d_|pat_)[A-Za-z0-9_-]{36,200})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Figma }

func (Scanner) Keywords() []string { return []string{"figd_", "figpat_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Figma,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyToken(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret)
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Figma-Token", token)

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
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
