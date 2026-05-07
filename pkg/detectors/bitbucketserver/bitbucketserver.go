// Package bitbucketserver detects Bitbucket Server (Data Center, formerly
// Stash) HTTP access tokens and personal access tokens.
//
// Bitbucket Server is self-hosted; the verify endpoint
// (`/rest/api/1.0/users/<user>` or `/rest/api/latest/projects`) lives at the
// customer's own host, which is rarely embedded next to the token. Probing a
// guessed host would be a covert scan against unrelated infrastructure, so we
// surface unverified-by-design.
//
// Two distinct token shapes:
//   - HTTP access token: `BBDC-<base64url>` (~70 chars, project/repo scope).
//   - PAT minted by /plugins/servlet/access-tokens: 40 hex chars near the
//     `bitbucket` keyword.
package bitbucketserver

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	// Bitbucket Server prefixes its data-center HTTP access tokens with
	// `BBDC-` followed by a long base64url body (no padding). Length floor
	// at 40 absorbs the encoded-bytes minimum.
	httpAccessRe = regexp.MustCompile(`\b(BBDC-[A-Za-z0-9_-]{40,})\b`)
	// Personal access tokens are a 40-char base62 run; we keyword-gate
	// because that shape is generic.
	patRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)
)

var contextKeywords = []string{"bitbucket", "stash", "bbserver", "bb_pat"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BitbucketServer }

func (Scanner) Keywords() []string { return []string{"BBDC-", "bitbucket"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	for _, m := range httpAccessRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.BitbucketServer,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}

	lower := strings.ToLower(string(data))
	patHits := patRe.FindAllSubmatchIndex(data, -1)
	for _, h := range patHits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Skip if this token is the body of a BBDC- token already captured.
		if strings.Contains(token, "-") {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Bitbucket Cloud detector owns ATCTT3xFfGF0… tokens — skip those.
		if strings.HasPrefix(token, "ATCTT") {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.BitbucketServer,
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
