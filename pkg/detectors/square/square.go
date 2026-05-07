// Package square detects Square access tokens (production `EAAA…` and
// sandbox `sq0atp-…`) and verifies them via /v2/locations.
//
// Square production access tokens are 64 chars total starting with `EAAA`.
// Sandbox tokens use the `sq0atp-` prefix followed by 22 base64url chars.
// Both prefixes are distinctive enough to skip the keyword gate.
package square

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://connect.squareup.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Production tokens are 64 base64url chars beginning with EAAA. Sandbox is
// the legacy sq0atp- prefix. The combined alternation keeps a single match
// loop in FromData.
var keyRe = regexp.MustCompile(`\b(EAAA[A-Za-z0-9_-]{60}|sq0atp-[A-Za-z0-9_-]{22})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Square }

func (Scanner) Keywords() []string { return []string{"EAAA", "sq0atp-"} }

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
			DetectorType: detectors.Square,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/locations", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	// Square requires the Square-Version header on every API call. Without it
	// the gateway returns 400, which would invert our verify signal.
	req.Header.Set("Square-Version", "2024-08-21")

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
