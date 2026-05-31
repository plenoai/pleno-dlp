// Package confluence detects Atlassian Confluence Cloud API tokens near a
// "confluence" keyword.
//
// Verify is unverified-by-design: the Confluence Cloud API
// (GET /wiki/rest/api/user/current) requires HTTP Basic auth as
// `email:api_token` against the tenant's own `<workspace>.atlassian.net`
// host. Neither the account email nor the workspace subdomain appears in the
// token or anywhere we can reliably derive from the chunk, so a live probe
// could only false-negative or fire against unrelated infrastructure.
// Surfacing unverified findings still helps operators rotate.
//
// Token shape: Atlassian Cloud API tokens carry the fixed `ATATT3xFfGF0`
// prefix followed by ~150 chars of base64url payload — mirroring the sibling
// `ATCTT3xFfGF0` shape the bitbucketcloud detector anchors. We discriminate
// Confluence from the Jira/Atlassian tokens that share the `ATATT` prefix via
// the "confluence" keyword window, and skip `ATCTT` tokens that belong to
// bitbucketcloud to avoid cross-detector double-fire.
package confluence

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Atlassian Cloud API tokens: fixed `ATATT3xFfGF0` prefix + base64url body.
// The bitbucketcloud detector anchors the sibling `ATCTT3xFfGF0` shape the
// same way (60-200 trailing chars).
var tokenRe = regexp.MustCompile(`\b(ATATT3xFfGF0[A-Za-z0-9_=+/-]{60,200})\b`)

// minTokenEntropy drops low-entropy lookalikes (repeated/padded runs) that
// survive the prefix regex.
const minTokenEntropy = 3.5

var contextKeywords = []string{"confluence", "confluence_api", "confluence_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Confluence }

// ATATT3xFfGF0 in Keywords gives the engine a precise prefilter so the regex
// only runs on chunks that actually carry the Atlassian token prefix.
func (Scanner) Keywords() []string { return []string{"confluence", "ATATT3xFfGF0"} }

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
		// Bitbucket Cloud owns ATCTT3xFfGF0… tokens — defensive skip in case
		// the prefix regex ever loosens.
		if strings.HasPrefix(token, "ATCTT") {
			continue
		}
		if !detectors.HasMinEntropy(token, minTokenEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Confluence,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
