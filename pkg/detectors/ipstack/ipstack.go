// Package ipstack detects ipstack IP-geolocation access keys — 32 hex
// characters within 40 bytes after the `ipstack` keyword. Verified via
// /check on api.ipstack.com with the access_key query parameter.
package ipstack

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.ipstack.com"

const maxVerificationResponseBytes = 1 << 20

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

var tokenRe = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`(?i:ipstack)(?:.|[\n\r]){0,40}?\b([a-fA-F0-9]{32})\b`)
})

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.IPStack }

func (Scanner) Keywords() []string { return []string{"ipstack"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe().FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{DetectorType: detectors.IPStack, Raw: []byte(token), Redacted: redact(token)}
		if verify {
			res.Verified, res.VerificationErr = s.Verify(ctx, token)
		}
		out = append(out, res)
	}
	return detectors.SafeResults(out), nil
}

// ipstack answers HTTP 200 for both valid and invalid keys; the verdict lives in the JSON error code.
// https://ipstack.com/documentation#errors
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("access_key", secret)
	q.Set("fields", "ip")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/check?"+q.Encode(), nil)
	if err != nil {
		return false, fmt.Errorf("ipstack verify: build request")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// net/url errors embed the request URL, which carries the access key.
		return false, fmt.Errorf("ipstack verify: request failed")
	}
	defer resp.Body.Close()
	accepted, err := detectors.ClassifyVerifyHTTP(resp, nil, []int{http.StatusOK}, nil)
	if err != nil || !accepted {
		return false, err
	}
	var body struct {
		Success *bool   `json:"success"`
		IP      *string `json:"ip"`
		Error   *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := detectors.DecodeVerifyJSON(resp.Body, maxVerificationResponseBytes, &body); err != nil {
		return false, fmt.Errorf("ipstack verify: decode response")
	}
	if body.Error == nil {
		if body.IP == nil || (body.Success != nil && !*body.Success) {
			return false, fmt.Errorf("ipstack verify: response missing lookup result")
		}
		return true, nil
	}
	switch body.Error.Code {
	case 101, 102: // invalid_access_key, inactive_user
		return false, nil
	case 104, 105: // usage_limit_reached, function_access_restricted: key authenticated, plan-limited
		return true, nil
	default:
		return false, fmt.Errorf("ipstack verify: ambiguous error code %d", body.Error.Code)
	}
}

func redact(t string) string { return t[:8] + "..." }

func init() { detectors.Register(Scanner{}) }
