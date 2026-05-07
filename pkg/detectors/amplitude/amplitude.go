// Package amplitude detects Amplitude analytics API key + secret pairs near
// the `amplitude` keyword. Amplitude uses a 32-hex API key with a paired
// 32-hex secret key. Raw carries the API key, RawV2 carries the secret.
// Verified via /api/2/usersearch on amplitude.com using HTTP Basic auth
// (key as user, secret as password).
package amplitude

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://amplitude.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-char lowercase hex matches both Amplitude API keys and secret keys.
var hexRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"amplitude", "amplitude_api", "amplitude_key", "amplitude_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Amplitude }

func (Scanner) Keywords() []string { return []string{"amplitude"} }

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
			DetectorType: detectors.Amplitude,
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

// nearestOther finds another 32-hex match different from key within the same
// data; Amplitude pairs are typically declared on adjacent lines.
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

// Verify accepts the combined `key:secret` pair (Basic auth credentials).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/2/usersearch?user=test", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, sec)
	req.Header.Set("Accept", "application/json")

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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
