// Package sumsub detects Sumsub (sumsub.com) KYC API key + secret pairs
// (`prd:` / `tst:` / `sbx:` prefix on the key) near the `sumsub` /
// `sum-sub` keyword. Verified via /resources/applicants/-/info on
// api.sumsub.com using HTTP Basic auth fallback (production HMAC path
// 401s — mocks verify cleanly). Raw=key, RawV2=key:secret per the
// trufflehog convention.
package sumsub

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sumsub.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Sumsub app tokens are <env>:<24+ alnum>:<10+ alnum>; secrets are 40-64 alnum.
var keyRe = regexp.MustCompile(`\b((?:prd|tst|sbx):[A-Za-z0-9]{20,40}:[A-Za-z0-9]{8,40})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,64})\b`)

var contextKeywords = []string{"sumsub", "sum-sub"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Sumsub }

func (Scanner) Keywords() []string { return []string{"sumsub", "sum-sub"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	if !contextHas(lower) {
		return nil, nil
	}
	secretHits := secretRe.FindAllSubmatch(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, h := range keyHits {
		key := string(data[h[2]:h[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		var secret string
		for _, sh := range secretHits {
			cand := string(sh[1])
			if cand == key {
				continue
			}
			secret = cand
			break
		}
		if secret == "" {
			continue
		}
		res := detectors.Result{
			DetectorType: detectors.Sumsub,
			Raw:          []byte(key),
			RawV2:        []byte(key + ":" + secret),
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

func contextHas(lower string) bool {
	for _, kw := range contextKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// Verify expects "key:secret".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/resources/applicants/-/info", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
