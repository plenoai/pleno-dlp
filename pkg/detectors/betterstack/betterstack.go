// Package betterstack detects Better Stack (formerly Logtail) API tokens —
// 24+ alnum tokens near the `betterstack` / `logtail` keyword. Verified via
// /api/v2/teams on uptime.betterstack.com with Bearer auth.
package betterstack

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://uptime.betterstack.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Better Stack tokens are 24-char alphanumeric with no public prefix (upstream
// trufflehog pins {24}; the Telemetry/Warehouse API docs show 24-char alnum
// examples e.g. "FczKcxEhjEDE58dBX7XaeX1q"). The exact upper bound is not
// authoritatively closed, so the lower bound 24 is sourced and the upper bound
// stays at 40 to preserve recall on longer dashboard tokens.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,40})\b`)

// minEntropy rejects git-SHA-shaped and other low-information alnum runs that
// clear the regex but lack key-grade randomness. 24-40 base62 has ample
// entropy headroom, so 3.5 over a full-variety charset does not cull real keys.
const minEntropy = 3.5

// contextRe is the windowed keyword gate. The bare strings.Contains over
// radius 256 matched English words ("logtail" rarely, but "betterstack"
// substrings in unrelated identifiers) and any token within a 256-char window
// of the vendor name. The arm regex requires an assignment-style
// token/key/secret near the vendor word; bare vendor keywords remain in
// Keywords() as the engine prefilter.
var contextRe = regexp.MustCompile(`(?i)(?:better[_-]?stack|better[_-]?uptime|logtail)[_-]?(?:api[_-]?)?(?:token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BetterStack }

func (Scanner) Keywords() []string { return []string{"betterstack", "logtail", "betteruptime"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BetterStack,
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
	window := lower[from:to]
	return contextRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/teams", nil)
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
