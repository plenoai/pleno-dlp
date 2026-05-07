// Package pingone detects PingOne worker app credentials — client_id +
// client_secret pair (each UUID or 36+ alnum) near the `pingone` keyword.
// Verified via /as/token oauth2 client_credentials on auth.pingone.com
// using HTTP Basic auth. Raw carries the client_id, RawV2 the secret.
package pingone

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://auth.pingone.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9\-_]{32,128})\b`)

var contextKeywords = []string{"pingone"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PingOne }

func (Scanner) Keywords() []string { return []string{"pingone"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
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
	id, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.PingOne,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify {
		v, err := s.Verify(ctx, id+":"+secret)
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
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/as/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
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
