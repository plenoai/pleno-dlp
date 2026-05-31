// Package drip detects Drip (getdrip.com) personal API tokens, issued from the
// user-settings page and used as the username in HTTP Basic auth (token as
// username, blank password) against api.getdrip.com — verified read-only via
// /v2/accounts.
//
// Token format is NOT authoritatively documented: Drip's official API docs
// (developer.drip.com, DripEmail/api-docs) describe the token only as an
// "alphanumeric" Basic-auth username and never pin a length or charset, and
// trufflehog ships no upstream drip detector to mirror. The 32-char alnum
// shape here is therefore a heuristic, not a documented invariant. Because the
// length is unverified we do NOT tighten the regex further; instead the broad
// shape is disambiguated by (1) an assignment-anchor keyword arm regex within a
// 64-byte window, (2) a low-variety lowercase-hex guard (git SHAs / lockfile
// hashes), and (3) a conservative Shannon-entropy floor. See the research
// record / docs/detector-key-formats.md inconclusive-fallback path.
package drip

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.getdrip.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// gitSHALikeRe matches 32-char lowercase-hex strings (truncated git SHAs / lockfile hashes).
var gitSHALikeRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// minEntropy is a conservative floor: the token shape is base62 (high variety),
// but because the length/charset are not authoritatively documented we use the
// recall-safe 3.0 threshold rather than 3.5 to avoid silently culling real
// tokens. It rejects only the lowest-information 32-char runs that clear the
// regex.
const minEntropy = 3.0

// armRe is the assignment-anchor keyword gate, replacing the prior bare
// strings.Contains over the broad keyword list. It matches drip-flavored
// credential assignment shapes (drip api token / key / secret) so the gate
// fires on real config lines, not on any chunk that merely mentions "getdrip".
// The bare "getdrip" prefilter stays in Keywords().
var armRe = regexp.MustCompile(`(?i)(?:getdrip|drip)[_-]?(?:api[_-]?)?(?:token|key|secret|account[_-]?id)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Drip }

func (Scanner) Keywords() []string { return []string{"getdrip"} }

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
		if gitSHALikeRe.MatchString(token) {
			continue
		}
		// Conservative entropy floor: reject the lowest-information 32-char
		// runs that clear the broad regex but lack key-grade randomness.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Drip,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
