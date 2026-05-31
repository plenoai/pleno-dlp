// Package avalara detects Avalara AvaTax credentials — a numeric account_id
// (7-12 digits) plus a license_key (typically 24-32 alphanumerics) appearing
// near an `avalara`/`avatax` assignment-anchor reference (radius 64, with a
// conservative 3.0 entropy floor on the license). Verified via
// /api/v2/utilities/ping
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

// armRe is the assignment-anchor gate: a `avalara`/`avatax` reference
// adjoining an account-id / license / key / secret token. It replaces a bare
// strings.Contains(window,"avalara") which armed on any prose mention of the
// vendor. The bare keywords stay in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)ava(lara|tax)[_\-]?(account([_\-]?id)?|license([_\-]?key)?|api[_\-]?(token|key)|token|key|secret)`)

// minLicenseEntropy is a conservative Shannon floor. Avalara's auth docs show
// a license-key example (123456789ABCDEF123456789ABCDEF) but do not formally
// pin its length or charset, so the documented length window (24-32) is kept
// and only a low 3.0 floor is applied — a hex-only key caps near 3.6 bits/char,
// so 3.5 would over-cull; 3.0 still rejects repetitive low-entropy filler.
const minLicenseEntropy = 3.0

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
		if !detectors.HasMinEntropy(v, minLicenseEntropy) {
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

// nearKeyword reports whether an avalara/avatax assignment-anchor reference
// (see armRe) appears within a tight window on either side of the candidate.
// Radius tightened 256 -> 64 to cut cross-context false positives.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
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
