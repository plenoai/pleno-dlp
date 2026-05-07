// Package vonage detects Vonage (Nexmo) API key + API secret pairs. The key
// is 8-char alnum and the secret is 16-char base64url; both shapes collide
// trivially with random alnum, so co-occurrence with `vonage` / `nexmo` /
// `vonage_api_key` / `vonage_api_secret` in a 256-byte window is mandatory.
//
// Vonage credentials authorize SMS sends and voice calls (real money on the
// hook), so verified hits surface SeverityCritical via engine default.
// Verification calls /v0.1/users on api.nexmo.com with HTTP Basic.
package vonage

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.nexmo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	keyRe    = regexp.MustCompile(`\b([A-Za-z0-9]{8})\b`)
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{16})\b`)
)

var contextKeywords = []string{
	"vonage",
	"nexmo",
	"vonage_api_key",
	"vonage_api_secret",
	"nexmo_api_key",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vonage }

func (Scanner) Keywords() []string { return []string{"vonage", "nexmo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
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
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret, ok := nearestSecret(k[2], data, secrets, key)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Vonage,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"api_key": key},
		}
		if verify {
			v, err := s.Verify(ctx, key, secret)
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

func (Scanner) Verify(ctx context.Context, key, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v0.1/users", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + secret))
	req.Header.Set("Authorization", "Basic "+auth)
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

func nearestSecret(keyStart int, data []byte, hits [][]int, keyValue string) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		candidate := string(data[h[2]:h[3]])
		if candidate == keyValue {
			continue
		}
		dist := abs(h[2] - keyStart)
		if dist < bestDist {
			bestDist = dist
			best = candidate
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
