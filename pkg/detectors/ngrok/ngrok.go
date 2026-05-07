// Package ngrok detects ngrok personal auth and API tokens (`2…`-prefixed,
// 40+ url-safe characters with an embedded `_`) and verifies them against
// /api/users/me on api.ngrok.com.
package ngrok

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.ngrok.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// ngrok tokens look like `<24 base62>_<27 base62>` totalling 52 chars,
// always starting with `2` (the version digit). We accept 40..80 and
// require an internal `_` to disambiguate from random base62 runs.
var tokenRe = regexp.MustCompile(`\b(2[A-Za-z0-9]{20,40}_[A-Za-z0-9]{20,40})\b`)

var contextKeywords = []string{"ngrok"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Ngrok }

func (Scanner) Keywords() []string { return []string{"ngrok"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Co-occurrence keeps the regex from firing on unrelated UUID-ish
		// blobs that happen to start with `2` and contain an underscore.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Ngrok,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	// ngrok's API requires this version header on every request.
	req.Header.Set("Ngrok-Version", "2")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusNotFound:
		// 404 for /api/users/me on auth tokens (vs API tokens) — same
		// "wrong-scope" outcome; treat as unverified.
		return false, nil
	default:
		return false, nil
	}
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
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
