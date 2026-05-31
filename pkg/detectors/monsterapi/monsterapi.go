// Package monsterapi detects MonsterAPI inference API keys — long
// alphanumerics near the `monsterapi` keyword. Verified via /v1/health on
// api.monsterapi.ai with Bearer auth.
package monsterapi

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.monsterapi.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style MonsterAPI reference that must appear within a
// tight window of the candidate. No authoritative source pins the token
// prefix/length/charset (the official docs only show a `YOUR_BEARER_TOKEN`
// placeholder), so the regex length stays as-is and recall is preserved by
// gate-tightening rather than format-narrowing. The bare keywords below remain
// the engine prefilter via Keywords().
var armRe = regexp.MustCompile(`(?i)monster[_\-]?api[_\-]?(token|key|secret)?`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MonsterAPI }

func (Scanner) Keywords() []string { return []string{"monsterapi", "monster_api"} }

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
		// Conservative entropy floor: with no documented format we cannot pin a
		// length, so a low-variety run that happens to satisfy the alnum regex
		// (e.g. a hex digest or a repeated-char string) is rejected. 3.0 is the
		// recall-safe floor from docs/detector-key-formats.md — high enough to
		// drop obvious non-secrets, low enough not to cull real random tokens.
		if !detectors.HasMinEntropy(token, 3.0) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.MonsterAPI,
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

// nearKeyword reports whether a `monster[_-]?api[_-]?(token|key|secret)?`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby MONSTERAPI_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/health", nil)
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
