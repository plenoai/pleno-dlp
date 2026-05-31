// Package trulioo detects Trulioo (trulioo.com) GlobalGateway API keys
// near the `trulioo` keyword. Verified via /customer/v1/configuration/
// countrysubdivisions on api.globaldatacompany.com with x-trulioo-api-key
// header.
package trulioo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.globaldatacompany.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Trulioo issues OAuth2 client credentials (client_id/client_secret, NAPI v3)
// or legacy Basic-Auth username:password — neither carries a documented prefix,
// fixed length, or charset (credentials are provisioned by a Customer Success
// Manager, not self-serve, and the format is not authoritatively published).
// trufflehog ships no upstream trulioo detector to mirror. The 32-64 alnum
// shape is therefore a loose, non-authoritative bound retained for recall; the
// disambiguation comes from the arm-regex keyword gate plus a conservative
// entropy floor, NOT from a pinned length we cannot cite.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy is the conservative floor for the recall-safe fallback: it culls
// repetitive / structured 32-64 char runs (e.g. `AAAA...`, padded constants)
// without over-culling real credentials. 3.0 — not 3.5 — because no source
// documents the charset, so we must not assume base62-grade variety.
const minEntropy = 3.0

// armRe is the assignment-anchor keyword gate. It replaces a bare
// strings.Contains(window, "trulioo") so that prose mentions of "trulioo" /
// "globaldatacompany" no longer arm an arbitrary high-entropy neighbour; the
// match must look like a credential assignment (trulioo_api_key, trulioo-token,
// globaldatacompany_secret, etc.). The bare keyword stays in Keywords() as the
// engine prefilter.
var armRe = regexp.MustCompile(`(?i)(trulioo|globaldatacompany)[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Trulioo }

func (Scanner) Keywords() []string { return []string{"trulioo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Conservative entropy floor (fallback path): no authoritative charset,
		// so 3.0 only rejects clearly structured/repetitive runs.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Trulioo,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/customer/v1/configuration/countrysubdivisions/US", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-trulioo-api-key", secret)
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
