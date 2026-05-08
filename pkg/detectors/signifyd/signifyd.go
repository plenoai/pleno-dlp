// Package signifyd detects Signifyd API key + team id pairs near the
// `signifyd` keyword. Paired credential — Raw=teamId,
// RawV2=teamId+":"+apiKey. Verified via HTTP Basic auth (apiKey + ":")
// on api.signifyd.com /v3/teams.
package signifyd

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.signifyd.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,80})\b`)

var contextKeywords = []string{"signifyd"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Signifyd }

func (Scanner) Keywords() []string { return []string{"signifyd"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var ident, token string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		if ident == "" {
			ident = v
			continue
		}
		if v == ident {
			continue
		}
		token = v
		break
	}
	if ident == "" || token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Signifyd,
		Raw:          []byte(ident),
		RawV2:        []byte(ident + ":" + token),
		Redacted:     redact(ident),
	}
	if verify {
		v, err := s.Verify(ctx, ident+":"+token)
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
	_, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3/teams", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(tok + ":"))
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
