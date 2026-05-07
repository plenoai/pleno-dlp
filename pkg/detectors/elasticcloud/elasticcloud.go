// Package elasticcloud detects Elastic Cloud / Elasticsearch API keys. The
// canonical encoded form is `<id>:<api_key>` base64-url, and the decoded form
// is colon-separated `<id>:<key>` where both halves are URL-safe base64.
//
// We accept both shapes and require co-occurrence with `elastic` /
// `elasticsearch` / `_security/_authenticate` in a 256-byte window because
// the `<base64>:<base64>` colon pair collides with arbitrary tokens.
//
// Verification is left unimplemented — Elastic Cloud deployments live on
// per-customer https://<deployment>.<region>.aws.found.io endpoints not
// present in the chunk. Surfaces under --unverified-results by design.
package elasticcloud

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// id:secret pair, both URL-safe base64. Lengths chosen to match observed
// Elastic Cloud API keys (id ~20 chars, secret 22-43 chars).
var pairRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{16,32}):([A-Za-z0-9_-]{20,48})\b`)

var contextKeywords = []string{
	"elastic",
	"elasticsearch",
	"elastic_cloud",
	"_security/_authenticate",
	"apikey",
	"es_api_key",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ElasticCloud }

func (Scanner) Keywords() []string { return []string{"elastic", "elasticsearch"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := pairRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		id := string(data[h[2]:h[3]])
		secret := string(data[h[4]:h[5]])
		key := id + ":" + secret
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.ElasticCloud,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"api_key_id": id},
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
