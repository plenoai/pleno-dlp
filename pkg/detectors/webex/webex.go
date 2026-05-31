// Package webex detects Cisco Webex (webex.com) API access tokens.
//
// Webex access tokens are 64-char lowercase hex strings — confirmed against
// the upstream trufflehog detector (github.com/trufflesecurity/trufflehog,
// pkg/detectors/webex), which anchors on `\b([a-f0-9]{64})\b`. A 64-char hex
// run is a generic shape (it collides with SHA-256 digests, content hashes,
// and other hex blobs), so a bare "webex" substring over a wide window is too
// loose a gate. We instead require a `webex…token/key/secret`-style reference
// within a tight 64-byte window AND apply a Shannon-entropy floor before
// surfacing a candidate.
//
// The entropy floor is 3.0 bits/char: a 16-symbol hex alphabet caps at ~4.0
// bits/char and a real token sits near ~3.6, so 3.0 culls runs of zeros /
// repeated nibbles without destroying recall (3.5 would over-cull hex — see
// the threshold guidance in pkg/detectors/entropy.go).
//
// Verified via /v1/people/me on webexapis.com with a Bearer header —
// read-only and confirms the user the token is bound to.
package webex

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://webexapis.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 64-char lowercase hex. Format and length confirmed against the upstream
// trufflehog webex detector (`\b([a-f0-9]{64})\b`). No public prefix exists to
// anchor on, so the keyword arm regex plus the entropy floor carry the
// false-positive load.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

// armRe is the assignment-style Webex reference that must appear within the
// proximity window. A bare "webex" substring (docs URLs, dependency names,
// comments, ciscospark mentions) is too weak; a "webex…token/key/secret" shape
// is what a real credential assignment or config key takes. The optional
// connector and `access` segment cover WEBEX_TOKEN, webex-access-token,
// webexApiKey, ciscospark_token, etc.
var armRe = regexp.MustCompile(`(?i)(?:webex|ciscospark)[_\-]?(?:access[_\-]?)?(?:api[_\-]?)?(?:token|key|secret)`)

// minEntropy rejects low-information 64-char hex runs (runs of zeros, repeated
// nibbles) that clear the regex but are not random tokens. 3.0 is the sane
// floor for hex; see pkg/detectors/entropy.go threshold guidance.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Webex }

// Keywords must include "webex" — without it the engine would have no
// prefilter and would evaluate the hex regex against every chunk.
func (Scanner) Keywords() []string { return []string{"webex"} }

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
		// A `webex…token/key/secret` reference within a tight window is
		// mandatory — 64-char hex runs are common (SHA-256 digests, content
		// hashes) and a bare "webex" substring is too weak a gate.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: low-information 64-char hex (zero runs, repeated
		// nibbles) that clears the regex but lacks token-grade randomness is
		// rejected even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Webex,
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

// nearKeyword reports whether a `webex…token/key/secret` reference appears
// within a tight window on either side of the token. The window spans both
// directions (not strict immediate precedence) so a token defined alongside a
// nearby WEBEX_TOKEN reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/people/me", nil)
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
