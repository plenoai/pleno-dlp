// Package rippling detects Rippling API tokens — 40+ char alphanumeric strings
// near the `rippling` keyword. Verified via /platform/api/me on
// api.rippling.com with Bearer auth.
//
// Format research (2026-06-01): Rippling's API key / access token is an opaque
// OAuth bearer credential. Neither the official API docs
// (developer.rippling.com — documents only `Authorization: Bearer <TOKEN>`) nor
// Rippling's own example repos (rippling-developer-portal-example, rippling-cli,
// which treat `access_token` as an opaque string) publish a prefix, fixed
// length, or charset. There is also no upstream trufflehog rippling detector to
// mirror. With no authoritative format to anchor on, we apply only recall-safe
// gate-tightening: a `rippling[_-]?(api[_-]?)?(token|key|secret)` assignment
// anchor within a tight 64-byte window plus a conservative Shannon entropy
// floor. We deliberately do NOT pin a length or charset — doing so without a
// documented spec would silently destroy recall.
package rippling

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.rippling.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe stays a bare 40+ alphanumeric run: the credential format is
// undocumented, so the keyword arm regex and entropy floor — not the token
// regex — carry the false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,})\b`)

// armRe is the assignment-style Rippling reference that must appear within the
// proximity window. A bare "rippling" substring (package names, doc links,
// comments) is too weak; "rippling_api_token" / "rippling-key" /
// "ripplingsecret" is the shape a real token assignment or config key takes.
// The bare "RIPPLING_API" / "RIPPLING_AUTH" / "RIPPLING_CREDENTIAL" env-var
// forms (no token/key/secret suffix) are themselves credible anchors, so the
// suffix is optional after "api" and "auth"/"credential" arm on their own.
var armRe = regexp.MustCompile(`(?i)rippling[_\-]?(api([_\-]?(token|key|secret))?|auth|credential|token|key|secret)`)

// minEntropy rejects low-entropy 40+ char runs that clear the alnum regex but
// are not random tokens (e.g. padded identifiers, repeated structure). Held at
// a conservative 3.0 because the charset is unknown — a higher floor risks
// over-culling a legitimately lower-variety opaque token.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Rippling }

func (Scanner) Keywords() []string { return []string{"rippling"} }

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
			DetectorType: detectors.Rippling,
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

// nearKeyword reports whether a `rippling[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions, so a token defined alongside a nearby
// RIPPLING_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/platform/api/me", nil)
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
