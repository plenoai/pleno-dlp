// Package dialpad detects Dialpad API tokens — long alphanumerics armed by a
// `dialpad[_-]?(api[_-]?)?(token|key|secret)` reference within a tight window.
// Verified via /api/v2/users on dialpad.com with Bearer auth.
//
// Dialpad publishes no authoritative key format (no prefix/length/charset; the
// docs only say to share the last 4 chars) and trufflehog has no dialpad
// detector, so this is conservative gate-tightening only: radius 256->64, an
// assignment-anchor arm regex in place of a bare keyword Contains, and a
// conservative HasMinEntropy(token, 3.0). The `{40,128}` length is left
// unpinned to preserve recall.
package dialpad

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://dialpad.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No authoritative source pins Dialpad's API-key length or charset: Dialpad's
// own docs deliberately omit it (they instruct users to share only the last 4
// chars) and trufflehog has no dialpad detector. So the length stays `{40,128}`
// — pinning a guessed length would silently destroy recall. Precision instead
// comes from the assignment-anchor arm regex + a conservative entropy floor.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,128})\b`)

// armRe is the assignment-style Dialpad reference that must appear within the
// proximity window. A bare "dialpad" substring (doc links, the dialpad.com
// host, marketing copy) is too weak a gate against a generic 40-128 char
// alphanumeric run; `dialpad[_-]?(api[_-]?)?(token|key|secret)` is the shape a
// real credential assignment or config key takes. The bare keyword stays in
// Keywords() as the cheap Aho-Corasick prefilter.
var armRe = regexp.MustCompile(`(?i)dialpad[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-128 char runs (padded placeholders,
// long repeated-character runs) that clear the alnum regex but are not random
// tokens. Conservative 3.0 floor: no authoritative charset is documented, so a
// 3.5 floor risks over-culling a real (possibly lower-variety) key.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DialPad }

func (Scanner) Keywords() []string { return []string{"dialpad"} }

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
		// Entropy gate: low-information 40-128 char runs that clear the alnum
		// regex but lack token-grade randomness are rejected even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.DialPad,
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

// nearKeyword reports whether a `dialpad[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby DIALPAD_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/users", nil)
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
