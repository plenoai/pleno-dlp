// Package mailjet detects Mailjet API key + API secret pairs (each 32 hex
// chars) near the `mailjet` keyword. Verified via /v3/REST/myprofile on
// api.mailjet.com using HTTP Basic auth (key as username, secret as
// password). Raw carries the key, RawV2 carries the secret.
package mailjet

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mailjet.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var hexRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"mailjet"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mailjet }

func (Scanner) Keywords() []string { return []string{"mailjet"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := hexRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	key, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.Mailjet,
		Raw:          []byte(key),
		RawV2:        []byte(secret),
		Redacted:     redact(key),
	}
	if verify {
		v, err := s.Verify(ctx, key+":"+secret)
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
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3/REST/myprofile", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, sec)
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
