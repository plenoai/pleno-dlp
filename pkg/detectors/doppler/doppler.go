// Package doppler detects Doppler service tokens (`dp.<scope>.<base64>` —
// scope is `st` for service tokens, `pt` for personal, `ct` for CLI). Verify
// uses Basic auth with the token as the username (Doppler's documented contract).
package doppler

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.doppler.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `dp.` + 2-3 char scope + `.` + 40+ base64url chars. The dp.<scope>. prefix
// is distinctive enough to skip a keyword gate.
var tokenRe = regexp.MustCompile(`\b(dp\.(?:st|pt|ct|sa|scim)\.[A-Za-z0-9_-]{40,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Doppler }

func (Scanner) Keywords() []string {
	return []string{"dp.st.", "dp.pt.", "dp.ct.", "dp.sa.", "dp.scim."}
}

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
			DetectorType: detectors.Doppler,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v3/me", nil)
	if err != nil {
		return false, err
	}
	// Doppler authenticates with Basic where the username is the token and
	// password is empty.
	req.SetBasicAuth(secret, "")

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
