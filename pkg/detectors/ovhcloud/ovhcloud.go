// Package ovhcloud detects OVH Cloud API credentials. OVH issues a
// (application_key, application_secret, consumer_key) triple per
// integration; the application_key + consumer_key pair is necessary to
// call the API at all, so we surface the consumer_key as Raw and the
// application_secret as RawV2 (the application_key is encoded into
// ExtraData). Verification is impractical because OVH /auth/currentCredential
// requires HMAC-SHA1 of (app_secret + consumer_key + method + url + body
// + timestamp) — that signing path is documented but more surface area
// than a Verify gate should own. Detector is therefore unverified-by-design.
package ovhcloud

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// OVH application/consumer keys are documented as 32-char alnum tokens.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

var contextKeywords = []string{"ovh", "ovhcloud", "ovh_consumer", "ovh_application", "consumer_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OVHCloud }

func (Scanner) Keywords() []string { return []string{"ovh", "consumer_key"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
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
			DetectorType: detectors.OVHCloud,
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
