// Package avalara detects Avalara AvaTax credentials — a numeric account_id
// (7-12 digits) plus a license_key (typically 24-32 alphanumerics) appearing
// near the `avalara` or `avatax` keyword. Verified via /api/v2/utilities/ping
// on rest.avatax.com using HTTP Basic auth (account_id as username, license
// as password). Raw carries the account_id, RawV2 carries the license.
package avalara

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://rest.avatax.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var accountRe = regexp.MustCompile(`\b([0-9]{7,12})\b`)
var licenseRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,32})\b`)

var contextKeywords = []string{"avalara", "avatax"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Avalara }

func (Scanner) Keywords() []string { return []string{"avalara", "avatax"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	lower := strings.ToLower(string(data))
	accs := accountRe.FindAllSubmatchIndex(data, -1)
	lics := licenseRe.FindAllSubmatchIndex(data, -1)
	if len(accs) == 0 || len(lics) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, 1)
	var account, license string
	for _, h := range accs {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		account = string(data[h[2]:h[3]])
		break
	}
	if account == "" {
		return nil, nil
	}
	for _, h := range lics {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == account {
			continue
		}
		license = v
		break
	}
	if license == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Avalara,
		Raw:          []byte(account),
		RawV2:        []byte(license),
		Redacted:     redact(account),
	}
	if verify {
		v, err := s.Verify(ctx, account+":"+license)
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
	account, license := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/utilities/ping", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(account, license)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
