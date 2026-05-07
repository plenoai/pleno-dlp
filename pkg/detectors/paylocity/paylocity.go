// Package paylocity detects Paylocity OAuth client_id + client_secret pairs
// near the `paylocity` keyword. Verified via /IdentityServer/connect/token on
// the gateway host (apigateway.paylocity.com production / sandbox host
// otherwise) — the per-account host isn't reliably in the chunk so verify
// requires apiBase override and ships unverified-by-default. Raw carries the
// client_id, RawV2 carries the client_secret.
package paylocity

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase overrides the verify host. Default empty disables verify.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var credRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

var contextKeywords = []string{"paylocity"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Paylocity }

func (Scanner) Keywords() []string { return []string{"paylocity"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := credRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	type cand struct {
		val string
	}
	creds := make([]cand, 0, len(hits))
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
		creds = append(creds, cand{val: v})
	}
	if len(creds) < 2 {
		return nil, nil
	}
	clientID, clientSecret := creds[0].val, creds[1].val
	res := detectors.Result{
		DetectorType: detectors.Paylocity,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientSecret),
		Redacted:     redact(clientID),
	}
	if verify && apiBase != "" {
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
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&scope=WebLinkAPI")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/IdentityServer/connect/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
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
