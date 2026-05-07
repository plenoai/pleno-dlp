// Package splunkhec detects Splunk HTTP Event Collector tokens (UUIDv4 near
// `splunk_hec` / `services/collector`). The bare UUID shape collides with
// arbitrary correlation ids, so co-occurrence with a Splunk-context keyword
// in a 256-byte window is mandatory.
//
// Verification is left unimplemented because HEC endpoints live on per-customer
// hostnames (https://<host>:8088/services/collector/event) that aren't in
// the chunk. Surfaces under --unverified-results by design.
package splunkhec

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

var contextKeywords = []string{
	"splunk_hec",
	"splunk-hec",
	"splunkhec",
	"services/collector",
	"hec_token",
	"splunk_token",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SplunkHEC }

func (Scanner) Keywords() []string { return []string{"splunk", "services/collector"} }

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
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.SplunkHEC,
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
