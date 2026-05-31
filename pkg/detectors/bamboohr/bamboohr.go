// Package bamboohr detects BambooHR API keys near the `bamboohr` keyword.
// Verified via /api/gateway.php/<co>/v1/employees/0 on `<co>.bamboohr.com`
// using HTTP Basic auth (key as username, `x` as password). The per-tenant
// subdomain isn't carried in the chunk, so verify requires apiBase override
// and ships unverified-by-default.
//
// Key format (cited): BambooHR's official API docs state "The API secret key
// is a 160-bit number expressed in hexadecimal form"
// (https://documentation.bamboohr.com/docs/getting-started). 160 bits / 4 bits
// per hex digit = exactly 40 hex characters, charset [a-fA-F0-9]. This is the
// hex / low-variety rubric case: pin the documented length 40, restrict the
// charset to hex (which alone rejects base62/UUID-with-dashes FP shapes), and
// floor entropy at 3.0 (hex entropy caps ~3.6, so 3.5 would over-cull real
// keys). Radius tightened 256 -> 64 with an assignment-anchor arm regex.
package bamboohr

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

// 40 hex chars = 160-bit secret expressed in hexadecimal form (cited above).
var tokenRe = regexp.MustCompile(`\b([a-fA-F0-9]{40})\b`)

// minEntropy rejects degenerate hex runs (repeated/sequential digits) that
// clear the regex but lack key-grade randomness. 3.0, not 3.5: hex's 16-symbol
// alphabet caps Shannon entropy near 3.6 bits/char, so 3.5 would cull real keys.
const minEntropy = 3.0

// contextRe is the windowed keyword gate. The bare "bamboohr" substring stays
// in Keywords() as the cheap prefilter; this arm regex anchors on the
// assignment-style forms so a random 40-hex SHA merely co-located with the word
// "bamboohr" within radius 64 is not promoted to a finding.
var contextRe = regexp.MustCompile(`(?i)bamboohr[_-]?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BambooHR }

func (Scanner) Keywords() []string { return []string{"bamboohr"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BambooHR,
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
	window := lower[from:to]
	return contextRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/employees/directory", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "x")
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
