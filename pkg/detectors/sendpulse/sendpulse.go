// Package sendpulse detects SendPulse client_id + client_secret pairs
// near the `sendpulse` keyword. Verified via /oauth/access_token on
// api.sendpulse.com (OAuth client_credentials grant). Raw=client_id,
// RawV2=client_id:client_secret per the trufflehog convention.
package sendpulse

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sendpulse.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"sendpulse"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SendPulse }

func (Scanner) Keywords() []string { return []string{"sendpulse"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var clientID, clientSecret string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		if clientID == "" {
			clientID = v
			continue
		}
		if v == clientID {
			continue
		}
		clientSecret = v
		break
	}
	if clientID == "" || clientSecret == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.SendPulse,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientID + ":" + clientSecret),
		Redacted:     redact(clientID),
	}
	if verify {
		v, err := s.Verify(ctx, clientID+":"+clientSecret)
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
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", id)
	form.Set("client_secret", sec)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/oauth/access_token", strings.NewReader(form.Encode()))
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
