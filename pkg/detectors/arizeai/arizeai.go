// Package arizeai detects Arize AI (arize.com) ML-observability API keys
// (40-80 alnum) near an arize_api_key-style assignment anchor. Verified via
// /v1/spaces on app.arize.com with Authorization Bearer header.
//
// Arize does not publish the key's prefix, length, or charset: the official
// docs (arize.com/docs/ax/security-and-settings/api-keys and the GraphQL
// programmatic-access guide) only state the full key is shown once at
// creation, with no example value or format spec, and there is no upstream
// trufflehog arizeai detector to mirror. The regex therefore keeps its
// open 40-80 alnum range (no documented length to pin) and disambiguation
// rests on the assignment-anchor arm regex plus a conservative 3.0 entropy
// floor rather than a length pin.
package arizeai

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.arize.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Arize reference that must appear within the
// proximity window. A bare "arize" substring is too weak a gate against a
// generic 40-80 alphanumeric run; `arize[_-]?(api[_-]?)?(token|key|secret)` is
// the shape a real credential assignment or config key takes. The bare "arize"
// keyword stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)arize[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor: Arize does not document the key's
// prefix, length, or charset (see package note), so we cannot pin a length
// or use the 3.5 high-variety floor without risking recall. 3.0 only rejects
// the most structured low-information 40-80 char runs while leaving real
// key-grade randomness untouched.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ArizeAI }

func (Scanner) Keywords() []string { return []string{"arize"} }

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
		// Entropy gate: low-information 40-80 char runs clear the alnum
		// regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ArizeAI,
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

// nearKeyword reports whether an `arize[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby ARIZE_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/spaces", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
