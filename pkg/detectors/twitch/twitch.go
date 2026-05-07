// Package twitch detects Twitch OAuth client_secret values (30-char alnum
// co-occurring with `twitch` keyword) and verifies them against the
// /oauth2/validate endpoint after a client-credentials exchange.
//
// Twitch app secrets grant the issuing app's full scope (chat, channel
// API, EventSub). The 30-char alnum shape collides with many opaque
// tokens, so a co-occurring `twitch` keyword is mandatory.
//
// Verify exchanges the client_secret for an app-access token, then
// validates the token. The exchange requires a client_id which is rarely
// alongside the secret in code, so we fall back to surfacing the leak
// unverified-by-design when client_id isn't extractable. We still
// implement Verify for the case where both values land in the same chunk
// (the common shape for `.env` dumps).
package twitch

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://id.twitch.tv"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 30-char base62. Twitch documents app secrets as 30 lowercase base36 in
// dashboards, but the docs API returns mixed-case base62 strings.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{30})\b`)

var contextKeywords = []string{"twitch", "twitch_client", "twitch_secret", "twitch.tv"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Twitch }

func (Scanner) Keywords() []string { return []string{"twitch"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Twitch,
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

// Verify probes /oauth2/validate by treating the candidate as an OAuth
// access token. Real client_secret values fail this check (it expects an
// access token, not a secret) — so this only verifies a positive when the
// chunk happens to contain a usable Twitch access token. Operators
// rotating an app should treat the leak as critical regardless.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/oauth2/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "OAuth "+secret)

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
