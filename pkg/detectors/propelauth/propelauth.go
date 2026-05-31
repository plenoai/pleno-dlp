// Package propelauth detects PropelAuth backend API keys — 40+ char
// alphanumeric strings near the `propelauth` keyword. Verified via
// /api/backend/v1/end_user_api_keys/validate on auth.propelauth.com with
// Bearer auth.
//
// FP hardening: PropelAuth does not publish an authoritative key format.
// Its docs only show truncated examples (e.g. <TOKEN> rendered as
// "dhopw42...") with no documented prefix, length, or charset, and there is
// no upstream trufflehog detector to mirror. A bare `[A-Za-z0-9]{40,}` run is
// a generic high-entropy shape (base64url blobs, hashes, build artifacts), so
// we cannot pin a length or anchor a prefix without destroying recall.
// Instead we apply recall-safe gate-tightening only: a tight 64-byte
// assignment-anchor arm regex replaces the radius-256 bare-substring gate, and
// a conservative Shannon entropy floor (3.0) rejects low-information runs. The
// bare "propelauth" keyword is retained as the engine prefilter.
package propelauth

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://auth.propelauth.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No authoritative length/charset/prefix is documented (see package doc), so
// the original 40+ alphanumeric run is preserved to protect recall. The
// false-positive load is carried by the arm regex and the entropy floor.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,})\b`)

// armRe is the assignment-style PropelAuth reference that must appear within
// the proximity window. A bare "propelauth" substring (docs URLs, SDK import
// paths, comments) is too weak; "propelauth_api_key" / "propelauth-token" /
// "propelauthapikey" is the shape a real key assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)propelauth[_-]?(api[_-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 40+ char runs that clear the alnum regex but
// are not random tokens. 3.0 is conservative: with no documented charset we do
// not assume the full base62 variety, so we avoid a 3.5 floor that could
// over-cull a genuine but lower-variety key.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PropelAuth }

func (Scanner) Keywords() []string { return []string{"propelauth"} }

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
		// Entropy gate: structured/low-information 40+ char runs (padded
		// identifiers, repeated patterns) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.PropelAuth,
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

// nearKeyword reports whether a `propelauth[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight 64-byte window on either side of the token.
// The window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby PROPELAUTH_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/backend/v1/end_user_api_keys/validate", nil)
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
