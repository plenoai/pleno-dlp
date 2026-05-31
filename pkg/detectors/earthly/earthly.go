// Package earthly detects Earthly Cloud secrets / tokens — long base62 near
// the `earthly` keyword. Verified via /api/v0/account/me on api.earthly.dev
// using Bearer auth.
package earthly

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.earthly.dev"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Earthly Cloud tokens are issued server-side; no authoritative source
// documents a prefix, fixed length, or charset (the cloud-api repo is
// protobuf stubs only, and the docs use opaque `<my-token>` placeholders).
// The shape stays a generic alphanumeric run — a tight keyword arm plus an
// entropy floor are required to keep this from matching arbitrary IDs.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,120})\b`)

// armRe is the assignment-style Earthly reference that must appear within the
// proximity window. A bare "earthly" substring (build-tool docs, Earthfile
// references, the `earthly/earthly` image name) is too weak a gate against a
// generic 40-120 alphanumeric run; `earthly[_-]?(api[_-]?)?(token|key|secret)`
// — plus the documented `EARTHLY_TOKEN` / `earthly_cloud` config keys — is the
// shape a real credential assignment takes.
var armRe = regexp.MustCompile(`(?i)earthly[_\-]?((api[_\-]?)?(token|key|secret)|cloud)`)

// minEntropy rejects low-information 40-120 char runs that clear the alnum
// regex but are not random tokens (padded placeholders, repeated characters).
// 3.0 is the conservative floor used when the charset is unknown — it culls
// degenerate runs without risking recall on a real (possibly base16/base32)
// token whose entropy could sit well below the 3.5 base62 expectation.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Earthly }

func (Scanner) Keywords() []string { return []string{"earthly"} }

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
		// Entropy gate: structured/low-information 40-120 char runs (e.g. a
		// padded placeholder or a long run of repeated characters) clear the
		// alnum regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Earthly,
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

// nearKeyword reports whether an `earthly[_-]?(api[_-]?)?(token|key|secret)`
// (or `earthly_cloud`) reference appears within a tight window on either side
// of the candidate. The window spans both directions (not strict immediate
// precedence) so a credential defined alongside a nearby EARTHLY_TOKEN
// reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v0/account/me", nil)
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
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
