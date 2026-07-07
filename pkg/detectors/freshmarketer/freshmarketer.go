// Freshmarketer accounts have per-tenant hosts, but the API key is also
// accepted on the canonical `app.freshmarketer.com` for the verify probe.
package freshmarketer

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.freshmarketer.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No authoritative source pins the exact length or charset for a
// freshmarketer key, so the length window is left wide and recall is
// protected by the entropy floor + arm regex rather than a guessed length.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{16,40})\b`)

// 3.0 is conservative: no documented charset/length lets us claim a higher
// floor without risking recall.
const minEntropy = 3.0

// armRe is the assignment-style freshmarketer reference that must appear within
// the radius window for a candidate to arm. Replaces a bare
// strings.Contains(window, "freshmarketer") that armed on any prose mention.
var armRe = regexp.MustCompile(`(?i)fresh[_\-]?marketer[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Freshmarketer }

func (Scanner) Keywords() []string { return []string{"freshmarketer"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Freshmarketer,
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

// The bare keyword "freshmarketer" stays in Keywords() as the cheap engine
// prefilter; this gate is the precise arm.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/crm/sales/api/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token token="+secret)
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
