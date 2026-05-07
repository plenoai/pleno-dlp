// Package lacework detects Lacework API access tokens (`<base64>_<hex>`
// shape co-occurring with `lacework`) and verifies them against
// /api/v2/AccessTokens.
//
// Lacework tokens are short-lived bearer tokens minted from a key+secret
// pair. The shape is a base64url body, an underscore, and a hex hash —
// distinctive enough that the keyword gate is mostly there to keep noise
// out of large code corpora.
package lacework

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lacework.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `<40+ base64url>_<32+ hex>`. We require the underscore-and-hex tail
// because that's what disambiguates Lacework from generic JWTs and
// other base64 tokens.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,}_[a-f0-9]{32,})\b`)

var contextKeywords = []string{"lacework", "lacework_account", "lacework_token", "lacework.net"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lacework }

func (Scanner) Keywords() []string { return []string{"lacework"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Lacework,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/AccessTokens", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
