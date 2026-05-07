// Package dwolla detects Dwolla application key + secret pairs (each 50+
// base64-style characters) near the `dwolla` keyword. Verified via /token on
// api.dwolla.com using HTTP Basic auth (key as username, secret as password)
// with grant_type=client_credentials. Raw carries the key, RawV2 carries the
// secret.
package dwolla

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.dwolla.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Dwolla credentials are 50+ chars of [A-Za-z0-9]; Dwolla docs publish 50-char
// shapes for keys and secrets.
var credRe = regexp.MustCompile(`\b([A-Za-z0-9]{50,})\b`)

var contextKeywords = []string{"dwolla"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Dwolla }

func (Scanner) Keywords() []string { return []string{"dwolla"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := credRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	// Need both halves to be near a dwolla keyword.
	type cand struct {
		val   string
		start int
	}
	creds := make([]cand, 0, len(hits))
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		creds = append(creds, cand{val: string(data[h[2]:h[3]]), start: h[2]})
	}
	if len(creds) < 2 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, 1)
	key, secret := creds[0].val, creds[1].val
	res := detectors.Result{
		DetectorType: detectors.Dwolla,
		Raw:          []byte(key),
		RawV2:        []byte(secret),
		Redacted:     redact(key),
	}
	if verify {
		v, err := s.Verify(ctx, key+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	out = append(out, res)
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, sec)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
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
