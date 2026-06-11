// Package asana detects Asana personal access tokens (PAT shape:
// 1/<16 digits>/<32 hex>) and verifies them against /users/me.
package asana

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.asana.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Asana PATs come in two observed formats:
//   - Legacy: 1/<16-digit gid>/<32 hex>   (slash-separated)
//   - Current: 1/<numeric gid>:<32 hex>   (colon-separated; gid ≥16 digits)
//
// Both use "1" (or "2" for forward-compat) as the version prefix.
// GID minimum length is 16 to exclude short numeric path segments.
var tokenRe = regexp.MustCompile(`\b([12]/[0-9]{16,}[/:]([a-f0-9]{32}))\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Asana }

// "1/" / "2/" alone would match too many shapes (date paths, etc.) so we
// pivot the keyword on "asana".
func (Scanner) Keywords() []string { return []string{"asana"} }

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
			DetectorType: detectors.Asana,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/1.0/users/me", nil)
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
	// Keep version + first slash + first 4 chars of gid = 6 chars.
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
