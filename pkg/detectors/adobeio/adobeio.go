// Package adobeio detects Adobe.io API key + client secret pairs and
// verifies them against the IMS (Identity Management Service) token
// endpoint. Adobe.io credentials are issued in pairs:
//
//   - api_key   — 32 lowercase hex (a.k.a. client_id)
//   - secret    — 32 alphanumerics, sometimes prefixed with "p8e-"
//
// Both must appear within the same chunk near an `adobeio` / `adobe.io`
// keyword. Verify performs a client_credentials POST to
// /ims/token/v3 — the response is 200 with a JSON envelope on success
// and 400/401 with `error="invalid_client"` on a wrong pair.
//
// We capture the api_key as Raw and the secret as RawV2 so RawV2-aware
// downstream tooling can rotate the right field.
package adobeio

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var imsBase = "https://ims-na1.adobelogin.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-hex client_id. Adobe rotates these as lowercase hex.
var keyRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

// Client secret — 32+ alphanumerics, optionally `p8e-` prefixed.
var secretRe = regexp.MustCompile(`\b((?:p8e-)?[A-Za-z0-9_-]{32,64})\b`)

var contextKeywords = []string{"adobeio", "adobe.io", "adobe_client", "adobe_api"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AdobeIO }

func (Scanner) Keywords() []string { return []string{"adobeio", "adobe.io"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		key := string(data[k[2]:k[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		// Co-occurrence is mandatory — 32-hex collides with md5/sha1.
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret, hasSecret := nearestSecret(k[2], data, secrets, key, 512)
		if !hasSecret {
			// Without a matching secret we cannot verify, and a bare 32-hex is
			// indistinguishable from a md5 hash. Skip.
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AdobeIO,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"client_id": key},
		}
		if verify {
			v, err := s.VerifyPair(ctx, key, secret)
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

// Verify implements detectors.Verifier with a single secret. Adobe.io
// requires both fields, so the single-secret form is documented as a
// no-op (returns false, nil) — callers should use VerifyPair.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return false, nil
}

// VerifyPair posts client_credentials to /ims/token/v3.
func (Scanner) VerifyPair(ctx context.Context, clientID, clientSecret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "openid")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, imsBase+"/ims/token/v3", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func nearestSecret(idStart int, data []byte, runs [][]int, exclude string, maxDistance int) (string, bool) {
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range runs {
		start, end := sm[2], sm[3]
		s := string(data[start:end])
		if s == exclude {
			continue
		}
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = s
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
