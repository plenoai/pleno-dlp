// Package nomic detects Nomic Atlas API keys — `nk-` prefix followed by a
// long base64url body. Verified via /v1/user on api-atlas.nomic.ai with
// Bearer auth.
package nomic

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api-atlas.nomic.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// nk- prefix + >=40 base64url chars — matches the documented Nomic shape.
var tokenRe = regexp.MustCompile(`\b(nk-[A-Za-z0-9_-]{40,})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Nomic }

func (Scanner) Keywords() []string { return []string{"nk-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h[1])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Nomic,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/user", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
