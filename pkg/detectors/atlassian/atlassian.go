// Package atlassian detects Atlassian Cloud API tokens (ATATT3-prefixed).
//
// Verify is intentionally NOT implemented and is infeasible, not merely
// unwired. Atlassian Cloud's GET /rest/api/3/myself requires HTTP Basic
// auth with the user's *email* as the username and the token as the
// password — the token is only half the credential, and we do not extract
// the email from the surrounding chunk. A token-only request returns 401
// regardless of token validity (a false negative, never a correct
// Verified=true). The <workspace>.atlassian.net host is also neither fixed
// nor derivable from the opaque token (no JWT claim). Surfacing unverified
// findings is still valuable — the operator can rotate the token without us
// confirming it's live. This detector is class b (unverified-by-design).
package atlassian

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Atlassian Cloud API tokens carry a fixed ATATT3 prefix followed by a long
// (~190+ char) base64url-ish body. Anchoring on the prefix and widening the
// length is the load-bearing FP defence: the previous bare `[A-Za-z0-9]{24}`
// run matched commit SHAs, build IDs, and generic identifiers near the word
// "atlassian". The real token shape cannot be confused with those.
var tokenRe = regexp.MustCompile(`\b(ATATT3[A-Za-z0-9_=-]{20,})`)

// minEntropy drops low-entropy bodies (e.g. a synthetic ATATT3 prefix glued
// onto a sequential/repeated run). Real tokens are high-entropy base64url.
const minEntropy = 3.5

var contextKeywords = []string{"atlassian.net", "atlassian_api", "atlassian"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Atlassian }

// "atlassian" alone — the hardcoded "ATLASSIAN_API" envvar pattern is
// already covered case-insensitively.
func (Scanner) Keywords() []string { return []string{"atlassian"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		// Entropy gate on the body after the ATATT3 prefix — a low-entropy
		// body is not a real opaque token.
		if !detectors.HasMinEntropy(token[len("ATATT3"):], minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		// Verified=false by design — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Atlassian,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 128
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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
