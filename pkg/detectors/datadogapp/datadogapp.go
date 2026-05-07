// Package datadogapp detects standalone Datadog Application keys (40 hex
// chars near `DD-APPLICATION-KEY` / `DD_APP_KEY` keywords).
//
// The existing `pkg/detectors/datadog` package surfaces 32-hex API keys and
// pairs them with an Application key when both are present in the same
// chunk. datadogapp is the complement: it surfaces lone 40-hex Application
// keys that show up without a sibling API key — for example in CI configs
// where the API key is supplied via a secrets manager and only the App key
// is checked into source.
//
// Verify is intentionally limited. Datadog's /api/v1/validate endpoint
// requires both DD-API-KEY and DD-APPLICATION-KEY headers; with only the
// App key in scope we can't authenticate. We surface the leak unverified
// and let pkg/detectors/datadog handle the paired path.
package datadogapp

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Datadog Application key: 40 hex chars (lower or upper).
var appRe = regexp.MustCompile(`\b([a-fA-F0-9]{40})\b`)

// 32-hex API keys nearby — used to skip the App key when the existing
// datadog detector will already surface the pair.
var apiRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

var contextKeywords = []string{"dd-application-key", "dd_application_key", "dd_app_key", "datadog_application_key", "datadog_app_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DatadogAppKey }

// The keyword gate is mandatory — 40 hex is sha1's exact shape and would
// otherwise fire on every git commit.
func (Scanner) Keywords() []string {
	return []string{"DD-APPLICATION-KEY", "DD_APPLICATION_KEY", "DD_APP_KEY"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := appRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	apis := apiRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Co-occurrence with a Datadog application keyword is mandatory:
		// otherwise we'd surface every sha1 in the chunk.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// If a 32-hex API key sits within the same window, the existing
		// `datadog` detector already surfaces the pair; skip to avoid a
		// duplicate finding from a different DetectorType.
		if hasNearbyAPIKey(h[2], apis) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.DatadogAppKey,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func hasNearbyAPIKey(start int, apis [][]int) bool {
	const radius = 256
	for _, a := range apis {
		if abs(a[2]-start) <= radius {
			return true
		}
	}
	return false
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
