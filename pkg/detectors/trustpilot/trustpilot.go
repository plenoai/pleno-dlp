// Package trustpilot detects Trustpilot Business API keys — long
// alphanumerics near the `trustpilot` keyword. Verified via
// /v1/business-units on api.trustpilot.com with the apikey query
// parameter.
package trustpilot

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.trustpilot.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

// armRe is the assignment-style Trustpilot reference that must appear within
// the proximity window. A bare "trustpilot" substring (widget script-src URLs,
// doc links, review-page anchors) is too weak a gate against a generic 32-128
// alphanumeric run; `trustpilot[_-]?(api[_-]?)?(token|key|secret)` is the shape
// a real credential assignment or config key takes. The bare "trustpilot"
// keyword stays in Keywords() as the engine prefilter.
//
// The Trustpilot API key length/charset is NOT authoritatively documented
// (developers.trustpilot.com shows only `YOUR-API-KEY-HERE` placeholders and
// no upstream trufflehog detector exists), so the {32,128} alnum range is left
// unchanged and the entropy floor is held conservative at 3.0 to protect
// recall — no length is pinned and no charset is narrowed on a guess.
var armRe = regexp.MustCompile(`(?i)trustpilot[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 32-128 char runs that clear the alnum regex
// but are not random tokens (e.g. padded placeholders, repeated characters).
// Held at 3.0 (conservative) because the true charset is undocumented; a
// higher floor would risk culling legitimate keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Trustpilot }

func (Scanner) Keywords() []string { return []string{"trustpilot"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
		// Entropy gate: structured/low-information 32-128 char runs (e.g. a
		// padded placeholder or a long run of repeated characters) clear the
		// alnum regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Trustpilot,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether a
// `trustpilot[_-]?(api[_-]?)?(token|key|secret)` reference appears within a
// tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a credential defined
// alongside a nearby TRUSTPILOT_API_KEY reference still arms.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("apikey", secret)
	target := strings.TrimRight(apiBase, "/") + "/v1/business-units?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
