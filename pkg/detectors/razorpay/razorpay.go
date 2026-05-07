// Package razorpay detects Razorpay key + secret pairs and verifies them
// against /v1/items with HTTP Basic auth (key as username, secret as
// password). The key is rzp_test_<14 alnum> or rzp_live_<14 alnum>; the
// secret is a 24+ char base62 string. Both are needed to make any API
// request, so the detector emits a Result only when both halves co-occur
// near the `razorpay` keyword. rzp_live_ pairs are SeverityCritical when
// verified — they can issue real charges.
package razorpay

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.razorpay.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	keyRe    = regexp.MustCompile(`\b(rzp_(?:test|live)_[A-Za-z0-9]{14,})\b`)
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,40})\b`)
)

var contextKeywords = []string{"razorpay", "razorpay_key", "razorpay_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Razorpay }

func (Scanner) Keywords() []string { return []string{"razorpay", "rzp_test_", "rzp_live_"} }

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
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret := nearestSecret(k[2], k[3], data, secrets, key)
		if secret == "" {
			continue
		}
		seen[key] = struct{}{}
		isLive := strings.HasPrefix(key, "rzp_live_")
		res := detectors.Result{
			DetectorType: detectors.Razorpay,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"key": key},
		}
		if verify {
			v, err := verifyPair(ctx, key, secret)
			res.Verified = v
			res.VerificationErr = err
			if v && isLive {
				res.Severity = detectors.SeverityCritical
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify with the colon-joined form so the Verifier interface still works.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	key, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, key, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, key, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/items?count=1", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)

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

func nearestSecret(keyStart, keyEnd int, data []byte, hits [][]int, key string) string {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		// Skip the key itself or the rzp_<env>_ prefix tail.
		if s == key || strings.HasPrefix(s, "rzp_") {
			continue
		}
		dist := h[2] - keyEnd
		if dist < 0 {
			dist = keyStart - h[3]
		}
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = s
		}
	}
	return best
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
