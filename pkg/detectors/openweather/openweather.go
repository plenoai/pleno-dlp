// Package openweather detects OpenWeather API keys — 32 hex characters
// within 40 bytes after the `openweather` keyword. Verified via
// /data/2.5/weather on api.openweathermap.org with the appid query parameter.
package openweather

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

var apiBase = "https://api.openweathermap.org"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

var tokenRe = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`(?i:openweather)(?:.|[\n\r]){0,40}?\b([a-fA-F0-9]{32})\b`)
})

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OpenWeather }

func (Scanner) Keywords() []string { return []string{"openweather"} }

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
		res := detectors.Result{DetectorType: detectors.OpenWeather, Raw: []byte(token), Redacted: redact(token)}
		if verify {
			res.Verified, res.VerificationErr = s.Verify(ctx, token)
		}
		out = append(out, res)
	}
	return detectors.SafeResults(out), nil
}

// OpenWeather returns 401 for unknown or unactivated keys: https://openweathermap.org/faq#error401
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("lat", "0")
	q.Set("lon", "0")
	q.Set("appid", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/data/2.5/weather?"+q.Encode(), nil)
	if err != nil {
		return false, fmt.Errorf("openweather verify: build request")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// net/url errors embed the request URL, which carries the API key.
		return false, fmt.Errorf("openweather verify: request failed")
	}
	defer resp.Body.Close()
	return detectors.ClassifyVerifyHTTP(resp, nil, []int{http.StatusOK}, []int{http.StatusUnauthorized})
}

func redact(t string) string { return t[:8] + "..." }

func init() { detectors.Register(Scanner{}) }
