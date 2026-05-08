// Package gigya detects SAP Customer Data Cloud (Gigya) API key + secret
// pairs near the `gigya` keyword. Unverified by design — Gigya routes per
// data center (`<region>.gigya.com`) and the apikey alone won't auth a
// privileged probe; verification fires only when an apiBase override is
// supplied.
package gigya

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Gigya API keys are `_` prefixed plus 28 base64url chars.
var keyRe = regexp.MustCompile(`(_[A-Za-z0-9_\-]{28,40})`)
var secretRe = regexp.MustCompile(`([A-Za-z0-9+/]{27}=)`)

var contextKeywords = []string{"gigya"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Gigya }

func (Scanner) Keywords() []string { return []string{"gigya"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 || len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, kh := range keyHits {
		if !nearKeyword(lower, kh[2], kh[3]) {
			continue
		}
		key := string(data[kh[2]:kh[3]])
		for _, sh := range secretHits {
			if !nearKeyword(lower, sh[2], sh[3]) {
				continue
			}
			secret := string(data[sh[2]:sh[3]])
			k := key + ":" + secret
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Gigya,
				Raw:          []byte(key),
				RawV2:        []byte(k),
				Redacted:     redact(key),
			}
			if verify && apiBase != "" {
				v, err := s.Verify(ctx, k)
				res.Verified = v
				res.VerificationErr = err
			}
			out = append(out, res)
		}
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

func (Scanner) Verify(ctx context.Context, pair string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(pair, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	form := url.Values{}
	form.Set("apiKey", parts[0])
	form.Set("secret", parts[1])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/accounts.getAccountInfo", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
