// Package swimlane detects Swimlane SOAR personal access tokens — long
// alnum strings near a `swimlane[_-]?(api[_-]?)?(token|key|secret)`
// assignment reference. Verified via /api/user/me on app.swimlane.com
// with the Private-Token header.
//
// No authoritative source documents the PAT prefix/length/charset: the
// Swimlane Python driver forwards the token as an opaque string and the
// only documented session token is a dotted JWT (which the alnum regex
// below does not match). The 40-80 length range is therefore left as-is
// to preserve recall; FP risk is reduced by tightening the proximity
// gate to an assignment-anchor arm regex within radius 64 and adding a
// conservative entropy floor — not by guessing a length.
package swimlane

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.swimlane.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Swimlane reference that must appear within the
// proximity window. No authoritative source documents the PAT length/charset
// (the Swimlane Python driver forwards the token as an opaque string and the
// session token is a dotted JWT, which this alnum regex does not match), so the
// length range is left untouched to preserve recall. A bare "swimlane"
// substring (doc links, the app.swimlane.com host, package names) is too weak a
// gate against a generic 40-80 alphanumeric run; the shape a real credential
// assignment or config key takes is `swimlane[_-]?(api[_-]?)?(token|key|secret)`.
var armRe = regexp.MustCompile(`(?i)swimlane[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor: no source pins the charset, so 3.0 (well
// below the 3.5 used for documented high-variety tokens) only rejects clearly
// structured 40-80 char runs (padded placeholders, repeated characters) that
// clear the alnum regex but are not random tokens.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Swimlane }

func (Scanner) Keywords() []string { return []string{"swimlane"} }

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
		// Entropy gate: structured/low-information 40-80 char runs (padded
		// placeholders, long runs of repeated characters) clear the alnum regex
		// but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Swimlane,
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

// nearKeyword reports whether a `swimlane[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby SWIMLANE_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/user/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Private-Token", secret)
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
