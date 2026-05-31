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

// BeyondTrust documents its API key as "a cryptographically strong random
// sequence of numbers hashed into a 128-character string"
// (https://docs.beyondtrust.com/bips/reference/beyondinsight-and-password-safe-api-usage).
// The length (128) is authoritatively pinned; the charset is NOT documented —
// the header example "PS-Auth key=c479a66f…c9484d" shows lowercase hex, but
// legacy GUID-format keys exist and the hash output charset is unstated. We
// keep the alnum class (a superset of hex) and gate on a conservative entropy
// floor rather than guessing a narrower charset.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{128})\b`)

// minEntropy uses the conservative 3.0 floor: the documented header example is
// lowercase hex, which caps around 3.6 bits/char, so a 3.5 floor would
// over-cull legitimate hex keys. 3.0 still rejects repetitive/structured
// 128-char runs that clear the length+charset regex.
const minEntropy = 3.0

// armRe is the windowed assignment-anchor gate. It replaces a bare
// strings.Contains over radius 256 (which fired on any incidental
// "beyondtrust"/"ps-auth" substring) with a vendor + key/token/secret arm
// regex evaluated within radius 64. The bare keywords remain in Keywords()
// as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)(?:beyond[_-]?trust|ps[_-]?auth)[_-]?(api[_-]?)?(token|key|secret)`)

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
		// Entropy gate: reject low-information 128-char runs (repeated chars,
		// structured padding) that satisfy the length+charset regex but lack
		// key-grade randomness.
		if !detectors.HasMinEntropy(token, minEntropy) {
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
