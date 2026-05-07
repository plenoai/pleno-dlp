// Package leaseweb detects Leaseweb API key + secret pairs near the
// `leaseweb` keyword. Leaseweb assigns a 32-hex API key and a paired
// 32-hex private secret used to compute an HMAC `X-Lsw-Sign` header.
// Raw carries the API key, RawV2 carries the secret. Verified via
// /v1/account on api.leaseweb.com using the `X-Lsw-Auth: <key>` header.
package leaseweb

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.leaseweb.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-char lowercase hex matches both Leaseweb keys and secrets.
var hexRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"leaseweb", "lsw_", "lsw_auth", "leaseweb_api"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Leaseweb }

func (Scanner) Keywords() []string { return []string{"leaseweb"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := hexRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		key := string(data[h[2]:h[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		secret := nearestOther(hits, i, data, key)
		if secret == "" {
			continue
		}
		seen[key] = struct{}{}
		seen[secret] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Leaseweb,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
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

func nearestOther(hits [][]int, idx int, data []byte, key string) string {
	for j, h := range hits {
		if j == idx {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v != key {
			return v
		}
	}
	return ""
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

// Verify accepts the combined `key:secret` pair. We check key validity via
// the `X-Lsw-Auth` header; the secret is held for offline HMAC signing on
// other endpoints (not exercised by /v1/account).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key := parts[0]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Lsw-Auth", key)
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
