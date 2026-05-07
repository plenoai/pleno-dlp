// Package mixpanel detects Mixpanel service-account credentials. Mixpanel
// service accounts come as a pair: an account name shaped <slug>.<8-char id>
// (e.g. "my-project.AbCdEfGh") and a 32-hex secret. Verification uses Basic
// auth against /api/2.0/me.
package mixpanel

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://mixpanel.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Service account name: lowercase slug (>=10 chars to skip generic
	// hostnames) + dot + 8-char base62 id.
	accountRe = regexp.MustCompile(`\b([a-z]{10,}\.[a-zA-Z0-9]{8})\b`)
	// Secret: 32 lowercase hex.
	secretRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mixpanel }

func (Scanner) Keywords() []string { return []string{"mixpanel"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	accounts := accountRe.FindAllSubmatchIndex(data, -1)
	if len(accounts) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)

	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(accounts))
	seen := map[string]struct{}{}
	for _, a := range accounts {
		account := string(data[a[2]:a[3]])
		if _, dup := seen[account]; dup {
			continue
		}
		// "mixpanel" must appear within 256 bytes of the account candidate —
		// the slug.id shape collides with hostnames (e.g. cdn.example1.AbCd).
		if !nearKeyword(lower, a[2], a[3]) {
			continue
		}
		seen[account] = struct{}{}
		secret, ok := nearestSecret(a[2], data, secrets)
		res := detectors.Result{
			DetectorType: detectors.Mixpanel,
			Raw:          []byte(account),
			Redacted:     redact(account),
		}
		if ok {
			res.RawV2 = []byte(secret)
			if verify {
				v, err := verifyPair(ctx, account, secret)
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
	return strings.Contains(lower[from:to], "mixpanel")
}

func nearestSecret(accountStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		dist := abs(start - accountStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	// secret is "<account>:<secret>".
	account, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, account, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, account, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/2.0/me", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(account, secret)

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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
