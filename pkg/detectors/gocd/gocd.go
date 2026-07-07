// Package gocd detects GoCD server access tokens (40-64 mixed-case
// base62) gated on the `gocd` keyword. GoCD is self-hosted, so we
// surface unverified-by-design — the server URL isn't in the chunk and
// is not derivable from the opaque bearer token, so there is no fixed
// endpoint to verify against (cf. sibling self-hosted CI detectors
// Jenkins / Bamboo / ConcourseCI).
//
// Because the token shape (40-64 alnum) collides with git SHA-1
// digests, SHA-256 content digests, and base64 blobs, matching is
// hardened with: a Shannon entropy floor, a hex-digest exclusion, and
// a two-tier proximity gate (explicit credential anchors get a moderate
// window; bare prose `gocd` mentions must be immediately adjacent).
package gocd

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,64})\b`)

// hexDigestRe matches a pure-hex run of exactly 40 (git SHA-1) or 64
// (SHA-256/blake2b) chars. GoCD tokens are mixed-case base62, so any
// token that is also a valid hex digest of these lengths is far more
// likely a commit hash or content digest than a credential. We reject
// those regardless of proximity to the `gocd` keyword, killing the
// dominant FP class (changelog/lockfile/SBOM lines that pin a build
// image by digest next to a `gocd` mention).
var hexDigestRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

// strongKeywordRe is an explicit GoCD credential anchor
// (`gocd_token`, `gocd_api`, `gocd_key`, `gocd_secret`, `gocd_server`,
// or `gocd:` / `gocd=`). These are intentional config/secret markers,
// so we allow a moderate proximity window around them.
var strongKeywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bgocd[_\-](?:api|token|key|secret|server)` +
	`|\bgocd[ \t]*[:=]` +
	`)`)

// weakKeywordRe is a bare prose mention of GoCD (`gocd` / `go.cd` as a
// word). Prose mentions appear in docs, changelogs and SBOMs right next
// to unrelated long alnum runs (commit hashes, base64 blobs, PGP
// fragments — `tag_test.go` carries runs like
// `mQGNBGB5V8gBDACfWWMs+...GOcDR...`). We only let a weak mention gate a
// token when it is *immediately* adjacent, not anywhere in a wide
// window.
var weakKeywordRe = regexp.MustCompile(`(?i)(?:\bgocd\b|\bgo\.cd\b)`)

const (
	// strongRadius bounds an explicit credential anchor to its token.
	strongRadius = 48
	// weakRadius bounds a bare prose `gocd` mention very tightly, so a
	// changelog sentence that merely names GoCD near a hash/blob does
	// not gate.
	weakRadius = 12
	// minEntropy rejects low-entropy / repetitive 40+ char runs (e.g.
	// padded placeholders) that are not credential-shaped.
	minEntropy = 3.0
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GoCD }

func (Scanner) Keywords() []string { return []string{"gocd", "go.cd"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	strongSpans := strongKeywordRe.FindAllIndex(data, -1)
	weakSpans := weakKeywordRe.FindAllIndex(data, -1)
	if len(strongSpans) == 0 && len(weakSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if hexDigestRe.MatchString(token) {
			continue
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(strongSpans, h[2], h[3], strongRadius) &&
			!nearKeyword(weakSpans, h[2], h[3], weakRadius) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.GoCD,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(kwSpans [][]int, start, end, radius int) bool {
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
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
