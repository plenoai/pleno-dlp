// Package spotify detects Spotify Web API client_id + client_secret pairs and
// verifies them by minting an OAuth client_credentials token at
// /api/token.
//
// Spotify client credentials are 32 lowercase hex chars (both id and secret).
// Both halves share the same shape, so we rely on co-occurrence + keyword
// gate to disambiguate. Leaked pairs grant the app's full configured scope,
// so paired hits are graded SeverityCritical.
package spotify

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://accounts.spotify.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32 lowercase hex.
var idRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"spotify", "spotify_client", "client_id", "client_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Spotify }

func (Scanner) Keywords() []string { return []string{"spotify"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := idRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	type cand struct {
		token string
		start int
	}
	cands := []cand{}
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		cands = append(cands, cand{token: token, start: h[2]})
	}
	if len(cands) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(cands))
	used := map[int]struct{}{}
	for i, c := range cands {
		if _, u := used[i]; u {
			continue
		}
		// Greedy pair: first unused candidate within 1KB.
		var partner string
		for j := i + 1; j < len(cands); j++ {
			if _, u := used[j]; u {
				continue
			}
			if cands[j].start-c.start > 1024 {
				break
			}
			partner = cands[j].token
			used[j] = struct{}{}
			break
		}
		used[i] = struct{}{}

		res := detectors.Result{
			DetectorType: detectors.Spotify,
			Raw:          []byte(c.token),
			Redacted:     redact(c.token),
		}
		if partner != "" {
			res.RawV2 = []byte(partner)
			res.Severity = detectors.SeverityCritical
			if verify {
				v, err := verifyPair(ctx, c.token, partner)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		out = append(out, res)
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
	id, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, id, sec string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	body := strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		// Spotify returns 400 invalid_client when credentials don't match —
		// treat as unverified rather than as a scan error.
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
