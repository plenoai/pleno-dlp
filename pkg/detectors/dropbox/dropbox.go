// Package dropbox detects Dropbox short-lived access tokens (`sl.…`) and
// long-lived app/refresh tokens, verifying them via /2/users/get_current_account.
//
// Dropbox short-lived OAuth access tokens always start with `sl.` followed by
// 130+ base64url chars. The legacy generated app tokens are 64 base62 chars
// without a recognisable prefix — those require the "dropbox" keyword window
// to surface, since the shape collides with many opaque tokens.
package dropbox

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.dropboxapi.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	shortRe  = regexp.MustCompile(`\b(sl\.[A-Za-z0-9_-]{130,})\b`)
	legacyRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{64})\b`)
)

var contextKeywords = []string{"dropbox", "dropbox_token", "dbx"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Dropbox }

// "sl." plus the "dropbox" keyword catches both shapes.
func (Scanner) Keywords() []string { return []string{"sl.", "dropbox"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	// Short-lived tokens: prefix is distinctive.
	for _, m := range shortRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Dropbox,
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

	// Legacy 64-char tokens require keyword co-occurrence.
	legacyHits := legacyRe.FindAllSubmatchIndex(data, -1)
	if len(legacyHits) > 0 {
		lower := strings.ToLower(string(data))
		for _, h := range legacyHits {
			token := string(data[h[2]:h[3]])
			if _, dup := seen[token]; dup {
				continue
			}
			if !nearKeyword(lower, h[2], h[3]) {
				continue
			}
			seen[token] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Dropbox,
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
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// /2/users/get_current_account is documented as POST with `null` body. An
	// empty body produces 400; `null` is the documented contract that yields
	// 200 on a valid token and 401 on an invalid one.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/2/users/get_current_account", strings.NewReader("null"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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
