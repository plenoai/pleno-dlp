// Package trello detects Trello API key + token pairs and verifies them
// against /1/members/me. Trello's API requires both fields:
//
//   - key   — 32 lowercase hex (Power-Up app key)
//   - token — 64 lowercase hex (user authorization token)
//
// We capture the key as Raw and the token as RawV2 to match the rest of the
// codebase's RawV2-aware pair convention. Co-occurrence with `trello` is
// mandatory — both shapes (32-hex, 64-hex) collide with sha1/sha256 digests
// otherwise.
package trello

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.trello.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	keyRe   = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
	tokenRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)
)

var contextKeywords = []string{"trello", "trello_key", "trello_token", "trello_api"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Trello }

func (Scanner) Keywords() []string { return []string{"trello"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(tokens) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		key := string(data[k[2]:k[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		// Co-occurrence is mandatory — 32-hex without `trello` nearby is far
		// more likely to be md5/sha-something than a Power-Up key.
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		token, ok := nearestToken(k[2], data, tokens)
		if !ok {
			// No companion token — without both halves the API can't
			// be probed, and a bare 32-hex is too noisy to surface.
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Trello,
			Raw:          []byte(key),
			RawV2:        []byte(token),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"key": key},
		}
		if verify {
			v, err := verifyPair(ctx, key, token)
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

// Verify with the colon-joined form so the trufflehog single-secret
// Verifier interface still works for tooling that doesn't know about
// RawV2.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	key, token, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, key, token)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, key, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	q := url.Values{}
	q.Set("key", key)
	q.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/1/members/me?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func nearestToken(keyStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		dist := abs(h[2] - keyStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[h[2]:h[3]])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
