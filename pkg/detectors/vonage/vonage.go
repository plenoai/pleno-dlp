// Package vonage detects Vonage (Nexmo) API key + API secret pairs. The key
// is 8-char alnum and the secret is 16-char base64url; both shapes collide
// trivially with random alnum, so co-occurrence with `vonage` / `nexmo` /
// `vonage_api_key` / `vonage_api_secret` in a 256-byte window is mandatory.
//
// Vonage credentials authorize SMS sends and voice calls (real money on the
// hook), so verified hits surface SeverityCritical via engine default.
//
// Verification calls GET /account/get-balance on rest.nexmo.com with HTTP
// Basic (key:secret). This is the documented Account API endpoint that the
// api_key/api_secret pair authenticates; it returns 200 with the account
// balance on valid credentials and 401 on bad ones. The earlier /v0.1/users
// target was wrong: that path belongs to the Application/Conversation API,
// which expects a JWT (application_id + private key), so Basic key:secret was
// rejected even for valid account credentials (false Verified=false).
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

var apiBase = "https://rest.nexmo.com"

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
			RawV2:        []byte(key + ":" + secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"api_key": key},
		}
		if verify {
			v, err := s.Verify(ctx, key+":"+secret)
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

// Verify satisfies detectors.Verifier. The paired credential is packed as
// "key:secret" (matching RawV2 and the jumio/qualys paired-detector
// convention) so the single-string Verifier interface applies to a key+secret
// pair.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/account/get-balance", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// ClassifyVerifyHTTP normalises the response so an ambiguous reply (500,
	// 429, transport failure) surfaces as a transient error rather than a
	// false "not valid" verdict. 200 → valid; 401/403 → explicit rejection.
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
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
