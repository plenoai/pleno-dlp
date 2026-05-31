// Package airbrake detects Airbrake user API keys. Per upstream trufflehog
// (pkg/detectors/airbrakeuserkey) the key is exactly 40 alphanumeric chars
// with no prefix — a generic shape that collides with commit SHAs, nonces,
// and base64/hex blobs — so a bare `airbrake` substring within a wide window
// is far too loose a gate. We pin the documented length (40), require an
// `airbrake[_-]?(api[_-]?)?(token|key|project|id)?` assignment-style
// reference within a tight 64-byte window of the candidate, AND gate on
// Shannon entropy before surfacing it. Verified via /api/v4/projects on
// api.airbrake.io using `?key=<token>` query parameter.
package airbrake

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.airbrake.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Airbrake user API keys are exactly 40 alphanumeric chars, no prefix.
// Source: upstream trufflehog pkg/detectors/airbrakeuserkey keyPat
// `[a-zA-Z-0-9]{40}`.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)

// armRe is the assignment-style Airbrake reference that must appear within the
// proximity window. A bare "airbrake" substring (dependency names, comments,
// dashboard URLs) is too weak; the shape a real key assignment or config key
// takes is `airbrake`, `airbrake_token`, `airbrake-api-key`, `airbrake_project`,
// etc. The token/key/project/id suffix is optional so a bare `airbrake=<key>`
// assignment still arms.
var armRe = regexp.MustCompile(`(?i)airbrake[_-]?(api[_-]?)?(token|key|secret|project|id)?`)

// minEntropy rejects low-information 40-char runs that clear the alnum regex
// but are not random keys (e.g. padded identifiers, repeated chars). 40-char
// alphanumeric is a high-variety charset, so 3.5 is the appropriate floor
// (per docs/detector-key-formats.md: no-prefix, fixed-length, high-variety).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Airbrake }

func (Scanner) Keywords() []string { return []string{"airbrake"} }

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
		// Entropy gate: structured/low-information 40-char runs (padded
		// identifiers, repeated chars) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Airbrake,
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

// nearKeyword reports whether an `airbrake[_-]?(api[_-]?)?(token|key|...)?`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby `airbrake_token` reference still arms.
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
	q.Set("key", secret)
	endpoint := strings.TrimRight(apiBase, "/") + "/api/v4/projects?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}

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
