// Package getstream detects Stream (getstream.io) chat / activity feed
// credentials — a paired api_key + api_secret (each 12+ alphanumeric) near
// the `getstream` / `stream_io` / `stream.io` / `streamio` keyword. Stream
// uses HMAC-signed tokens with timestamp; verifying the raw secret without
// generating a JWT first is impractical, so this is unverified-by-design.
// Raw carries the api_key, RawV2 carries the api_secret.
package getstream

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{12,80})\b`)

// keywordRe is the anchored Stream (getstream.io) marker. The bare
// `getstream` substring is a common Go method name (`req.GetStream()`)
// and the loose 12+-alnum token shape pairs every adjacent CamelCase
// identifier. Require a Stream credential anchor.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bgetstream\.io\b` +
	`|\bstream\.io\b` +
	`|\bstream_io\b` +
	`|\bstreamio\b` +
	`|\bstream[_\-](?:api[_\-]key|api[_\-]secret|app_id|api_secret)` +
	`|\bgetstream[_\-](?:api|token|key|secret)` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GetStream }

func (Scanner) Keywords() []string {
	return []string{"getstream", "stream_io", "stream.io", "streamio"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		key := string(data[h[2]:h[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		var sec string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand != key && nearKeyword(kwSpans, h2[2], h2[3]) {
				sec = cand
				break
			}
		}
		if sec == "" {
			continue
		}
		seen[key] = struct{}{}
		seen[sec] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.GetStream,
			Raw:          []byte(key),
			RawV2:        []byte(sec),
			Redacted:     redact(key),
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
