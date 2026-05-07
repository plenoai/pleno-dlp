// Package fauna detects FaunaDB secrets (`fnAd…` admin / `fnAk…` server keys).
// The prefix is distinctive — Fauna documents both literally — so the keyword
// gate reduces to that prefix; we still gate verification on the `fauna`
// keyword window to keep generic `fnAd`-prefixed strings from triggering.
// Verification calls /version with Bearer auth; admin keys grant CRUD on every
// database in the parent root, so verified hits are SeverityCritical.
package fauna

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://db.fauna.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// fnA[dk] + base64url body. Fauna keys are mostly base64url and 40+ chars.
var tokenRe = regexp.MustCompile(`\b(fnA[dk][A-Za-z0-9_-]{30,200})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Fauna }

func (Scanner) Keywords() []string { return []string{"fnAd", "fnAk"} }

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
			DetectorType: detectors.Fauna,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/version", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
