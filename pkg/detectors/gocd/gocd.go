// Package gocd detects GoCD server access tokens (>=40 alnum) gated on the
// `gocd` keyword window. GoCD is self-hosted, so we surface unverified-by-
// design — the server URL isn't in the chunk.
package gocd

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,64})\b`)

// keywordRe is the anchored GoCD marker. The 4-letter `gocd` substring
// can appear randomly inside long base64 blobs (PGP blocks in
// `tag_test.go` carry runs like `mQGNBGB5V8gBDACfWWMs+...GOcDR...`),
// so a `strings.Contains` window match fires next to unrelated alnum
// runs. Require either a GoCD anchor (`gocd_api`, `gocd_token`) or
// a word-bounded `\bgocd\b` / `\bgo\.cd\b`.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bgocd[_\-](?:api|token|key|secret|server)` +
	`|\bgocd\b` +
	`|\bgo\.cd\b` +
	`|\bgocd[ \t]*[:=]` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GoCD }

func (Scanner) Keywords() []string { return []string{"gocd", "go.cd"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
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

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
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
