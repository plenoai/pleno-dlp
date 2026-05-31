// Package expel detects Expel (MDR) API keys near the `expel` keyword.
// Verified via /api/v2/users/current on workbench.expel.io with an
// Authorization Bearer header.
package expel

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://workbench.expel.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Expel API tokens are opaque non-expiring Bearer access_tokens; Expel's
// docs and the pyexclient client do NOT publish a prefix, length, or
// charset (see research record). No authoritative source pins the length,
// so the 32-64 alnum range is left unchanged — narrowing it would silently
// destroy recall. Disambiguation is delegated to the arm-regex gate plus a
// conservative entropy floor.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy rejects low-information 32-64 char runs (padded placeholders,
// repeated characters, structured IDs) that clear the alnum regex but lack
// token-grade randomness. 3.0 is deliberately conservative: with an
// undocumented charset we cannot assume the high variety that would justify
// 3.5, and an over-tight floor would cull real tokens.
const minEntropy = 3.0

// armRe is the assignment-style Expel reference that must appear within the
// proximity window. A bare "expel" substring (prose, doc links, the
// workbench.expel.io host in a script-src) is too weak a gate against a
// generic 32-64 alphanumeric run; `expel[_-]?(api[_-]?)?(token|key|secret)`
// is the shape a real credential assignment or config key takes. The bare
// "expel" keyword stays in Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)expel[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Expel }

func (Scanner) Keywords() []string { return []string{"expel"} }

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
		// Entropy gate: low-information 32-64 char runs (padded placeholders,
		// repeated characters, structured IDs) clear the alnum regex but are
		// not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Expel,
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

// nearKeyword reports whether an `expel[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby EXPEL_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/users/current", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
