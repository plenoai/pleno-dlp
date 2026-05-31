// Package forter detects Forter fraud-prevention API keys — long
// hex/base64 strings near a `forter` keyword. Verified via /v2/orders
// on api.forter.com with HTTP Basic auth (key as username).
package forter

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.forter.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe stays at the original {40,80} alphanumeric shape: Forter's official
// docs (Basic auth, "use the api key as the username, leave the password
// empty") and the Descope/PaymentsOS integration guides all confirm the
// credential is a Site ID + Secret Key pair, but none publish a length,
// charset, or prefix, and trufflehog ships no forter detector. With no
// authoritative format to anchor on, pinning a length/charset would risk
// silently destroying recall, so the regex is left as-is and only the
// recall-safe gates below are tightened.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Forter reference that must appear within the
// proximity window. A bare "forter" substring (script-src URLs to
// *.api.forter-secure.com, doc links, the portal host) is too weak a gate
// against a generic 40-80 alphanumeric run; `forter[_-]?(api[_-]?)?(token|
// key|secret)` is the shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)forter[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-80 char runs (padded placeholders,
// repeated characters, structured IDs) that clear the alnum regex but lack
// key-grade randomness. 3.0 is the conservative floor used when the real
// charset is undocumented — 3.5 would over-cull a possibly hex/low-variety key.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Forter }

func (Scanner) Keywords() []string { return []string{"forter"} }

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
		// Entropy gate: structured/low-information 40-80 char runs clear the
		// alnum regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Forter,
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
	return out, nil
}

// nearKeyword reports whether a `forter[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby FORTER_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/status", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
