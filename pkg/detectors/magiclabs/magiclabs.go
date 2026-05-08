// Package magiclabs detects Magic (magic.link) secret API keys near the
// `magic` keyword. Magic uses `sk_live_` / `sk_test_` prefixed secret keys
// for server-side use; verified via /v1/admin/auth/user/get on api.magic.link
// with an X-Magic-Secret-Key header.
package magiclabs

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.magic.link"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Magic secret keys are sk_(live|test)_ + 32+ alnum chars.
var tokenRe = regexp.MustCompile(`\b(sk_(?:live|test)_[A-Za-z0-9]{20,64})\b`)

var contextKeywords = []string{"magic", "magiclink", "magic.link", "magiclabs"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MagicLabs }

func (Scanner) Keywords() []string { return []string{"sk_live_", "sk_test_", "magic"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
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
		res := detectors.Result{
			DetectorType: detectors.MagicLabs,
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/admin/auth/user/get", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Magic-Secret-Key", secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		// 400 here means the key was accepted but the request was missing
		// query params — distinguishes "valid key, missing arg" from 401.
		return resp.StatusCode == http.StatusOK, nil
	}
	return false, nil
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
