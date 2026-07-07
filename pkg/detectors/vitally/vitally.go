// Package vitally detects Vitally customer-success API tokens near the
// `vitally` keyword. Verified via /resources/v2024 on api.vitally.io
// with HTTP Basic auth (key as username, empty password).
package vitally

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.vitally.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches a 32-64 alnum run. The Vitally REST API key is passed as the
// Basic-auth username (key:""), but the official docs do not disclose the
// token's prefix, exact length, or charset (only that it is a "secret token"),
// and trufflehog ships no Vitally detector to mirror. With no authoritative
// format to pin, we keep the broad length range and lean on the assignment
// anchor + entropy floor to bound false positives without harming recall.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Vitally reference that must appear within the
// proximity window. A bare "vitally" substring (doc links, the vitally.io host,
// prose) is too weak a gate against a generic 32-64 alnum run;
// `vitally[_-]?(api[_-]?)?(token|key|secret)` is the shape a real credential
// assignment or config key takes. The bare keyword stays in Keywords() as the
// engine prefilter.
var armRe = regexp.MustCompile(`(?i)vitally[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor: with no documented charset we cannot
// assume key-grade variety, so 3.0 only rejects clearly low-information runs
// (padded placeholders, long repeats) without over-culling real tokens.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vitally }

func (Scanner) Keywords() []string { return []string{"vitally"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Vitally,
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

// nearKeyword reports whether a `vitally[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions so a credential defined alongside a nearby
// VITALLY_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/resources/v2024/users", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(secret + ":"))
	req.Header.Set("Authorization", "Basic "+auth)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
