// Package lightstep detects Lightstep / ServiceNow Cloud Observability API
// keys — long alphanumerics gated by a `lightstep[_-]?(api[_-]?)?(token|key|
// secret)` assignment-style reference within a tight proximity window, plus a
// conservative entropy floor. Verified via /public/v0.2/projects on
// api.lightstep.com with Bearer auth.
//
// The credential format is NOT authoritatively documented: the official docs
// (tokens-and-keys, create-and-manage-api-keys/access-tokens, api-overview)
// describe only the Bearer usage and one-year expiry, and trufflehog ships no
// lightstep detector to mirror. With no documented prefix/length/charset, the
// regex stays a generic 40-80 alnum run — pinning a length would destroy
// recall — and the arm regex + entropy floor (3.0, charset-agnostic) carry the
// false-positive defence instead.
package lightstep

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lightstep.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe is intentionally a generic alnum run: no authoritative source
// (Lightstep/ServiceNow Cloud Observability docs, nor any upstream trufflehog
// detector) documents a prefix, fixed length, or charset for the API
// key/access token, so pinning a length here would silently destroy recall.
// The arm regex + entropy floor below carry the disambiguation instead.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Lightstep reference that must appear within the
// proximity window. A bare "lightstep" substring (doc links, the
// api.lightstep.com host, package names) is too weak a gate against a generic
// 40-80 alphanumeric run; `lightstep[_-]?(api[_-]?)?(token|key|secret)` is the
// shape a real credential assignment or config key takes. The bare keyword
// stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)lightstep[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor. The credential charset is not
// authoritatively documented, so 3.0 (well below the ~3.5 a base62 key clears)
// only culls low-information runs — repeated chars, padded placeholders — that
// satisfy the alnum regex but cannot be real tokens. It does not assume base62.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lightstep }

func (Scanner) Keywords() []string { return []string{"lightstep"} }

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
		// Entropy gate: low-information 40-80 char runs (repeated characters,
		// padded placeholders) clear the alnum regex but cannot be real tokens.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Lightstep,
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

// nearKeyword reports whether a `lightstep[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby LIGHTSTEP_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/public/v0.2/projects", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
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
