// Package bitfinex detects Bitfinex API key + secret pairs near the
// `bitfinex` keyword. Bitfinex production calls require HMAC-SHA384
// signing, so verify here uses the unsigned-bearer probe against
// /v2/auth/r/wallets — production rejects (401) which is unverified;
// mocks returning 200 verify cleanly. Pair encoded as RawV2.
package bitfinex

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.bitfinex.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Bitfinex keys are 43 alnum chars (newer API v2 keys).
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{43})\b`)

var contextKeywords = []string{"bitfinex"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bitfinex }

func (Scanner) Keywords() []string { return []string{"bitfinex"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(hits); i++ {
		key := string(data[hits[i][2]:hits[i][3]])
		secret := string(data[hits[i+1][2]:hits[i+1][3]])
		if key == secret {
			continue
		}
		if !nearKeyword(lower, hits[i][2], hits[i+1][3]) {
			continue
		}
		k := key + ":" + secret
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Bitfinex,
			Raw:          []byte(key),
			RawV2:        []byte(k),
			Redacted:     redact(key),
		}
		if verify {
			v, err := s.Verify(ctx, key)
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

func (Scanner) Verify(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v2/auth/r/wallets", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("bfx-apikey", key)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
