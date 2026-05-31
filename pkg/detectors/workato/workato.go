// Package workato detects Workato API auth tokens. Per the official docs
// (https://docs.workato.com/api-mgmt/auth-token.html) the auth token is a
// 64-character lowercase hexadecimal string, passed in the `api-token:`
// request header, e.g. `api-token: <64-HEX-TOKEN>`. A bare hex run has no
// distinguishing prefix, so the false-positive load is carried by (1) an
// assignment-style `workato[_-]?(api[_-]?)?(token|key|secret)` reference
// within a tight window and (2) a Shannon-entropy floor. Hex charset caps
// entropy near 3.6 bits/char, so the floor is 3.0 (3.5 would over-cull
// genuine hex tokens). Verification calls /api/users/me on www.workato.com.
package workato

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://www.workato.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches the documented 64-char lowercase-hex auth token. Length and
// charset are both authoritatively documented (docs.workato.com auth-token),
// so pinning them does not risk recall.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

// armRe is the assignment-style Workato reference that must appear within the
// proximity window. A bare "workato" substring (dependency names, doc URLs,
// comments) is too weak a gate; the shape a real token assignment or config
// key takes is `workato_token` / `workato-api-key` / `workatoSecret` etc.
var armRe = regexp.MustCompile(`(?i)workato[_-]?(api[_-]?)?(token|key|secret)`)

// minEntropy rejects low-information 64-char hex runs that clear the regex but
// are not random tokens (e.g. repeated/structured digests). Hex tops out near
// 3.6 bits/char, so 3.0 is conservative and recall-safe.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Workato }

// Keywords keeps the bare "workato" prefilter so the engine cheaply skips
// chunks with no Workato reference; the precise gate lives in armRe.
func (Scanner) Keywords() []string { return []string{"workato"} }

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
		// An assignment-style `workato...(token|key|secret)` reference within a
		// tight window is mandatory — 64-char hex runs are common (git object
		// ids, sha-256 digests, content hashes).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information hex runs (repeated nibbles,
		// padded digests) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Workato,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/users/me", nil)
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

// nearKeyword reports whether an armRe reference appears within a tight window
// on either side of the token. The window spans both directions (not strict
// immediate precedence) so a token defined alongside a nearby WORKATO_TOKEN
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
