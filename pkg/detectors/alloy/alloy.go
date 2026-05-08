// Package alloy detects Alloy KYC API token + secret pairs near the
// `alloy` keyword. Verified via /v1/journeys on sandbox.alloy.co with
// HTTP Basic auth (token:secret). Raw=token, RawV2=token:secret per the
// trufflehog convention.
package alloy

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://sandbox.alloy.co"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"alloy"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Alloy }

func (Scanner) Keywords() []string { return []string{"alloy"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var token, secret string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		if token == "" {
			token = v
			continue
		}
		if v == token {
			continue
		}
		secret = v
		break
	}
	if token == "" || secret == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Alloy,
		Raw:          []byte(token),
		RawV2:        []byte(token + ":" + secret),
		Redacted:     redact(token),
	}
	if verify {
		v, err := s.Verify(ctx, token+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	tok, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/journeys", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(tok + ":" + sec))
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
