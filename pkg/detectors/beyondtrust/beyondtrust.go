// Package beyondtrust detects BeyondTrust (privileged access management)
// API tokens near the `beyondtrust` keyword. Unverified by design —
// BeyondTrust deployments use per-tenant hosts (`<id>.beyondtrustcloud.com`
// for SaaS, customer-hosted on-prem otherwise), so verify only fires when
// an apiBase override is supplied (canonical probe is /api/public/v3/Auth
// with Authorization PS-Auth header).
package beyondtrust

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// BeyondTrust API keys are 64-128 alnum chars (long entropy on the
// PS-Auth scheme). We accept the conservative range.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{64,128})\b`)

var contextKeywords = []string{"beyondtrust", "beyond-trust", "ps-auth"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BeyondTrust }

func (Scanner) Keywords() []string { return []string{"beyondtrust", "ps-auth"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BeyondTrust,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/api/public/v3/Auth/SignAppin", nil)
	if err != nil {
		return false, err
	}
	// PS-Auth uses a structured header: PS-Auth key=<key>; runas=<user>;
	// We send only the key half — full verification would require runas.
	req.Header.Set("Authorization", "PS-Auth key="+secret+";")
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
