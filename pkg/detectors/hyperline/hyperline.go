// Package hyperline detects Hyperline (hyperline.co) billing API keys.
//
// Per Hyperline's API authentication docs, API keys are prefixed with `prod_`
// or `test_` to distinguish environments and are passed as a Bearer token. The
// docs do NOT publish the length or charset of the random tail, so we anchor on
// the documented prefix (the strong distinguishing signal) rather than guessing
// a length — pinning an undocumented length would silently destroy recall. The
// prefix carries most of the FP load; we keep a conservative entropy floor and a
// tight assignment-anchor keyword gate as belt-and-suspenders.
// Source: https://docs.hyperline.co/llms-full.txt (auth section).
// Verified via /v1/customers on api.hyperline.co with Bearer auth.
package hyperline

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.hyperline.co"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe anchors on the documented `prod_`/`test_` prefix. The random tail is
// `[A-Za-z0-9]` of undocumented length; we require >=16 chars (a recall-safe
// lower bound, not a pinned exact length) and let the prefix do the
// distinguishing work. Charset/length of the tail is NOT authoritatively
// documented — see package doc.
var tokenRe = regexp.MustCompile(`\b((?:prod|test)_[A-Za-z0-9]{16,})\b`)

// armRe is the assignment-style Hyperline reference that must appear within the
// proximity window. A bare "hyperline" substring (package names, doc URLs,
// comments) is too weak; `hyperline_api_token` / `hyperline-key` is the shape a
// real key assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)hyperline[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy prefixed runs that clear the regex but are not
// random tokens. Conservative 3.0 floor — base62 tokens sit well above this, so
// it culls obvious structured strings without trimming real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Hyperline }

func (Scanner) Keywords() []string { return []string{"hyperline"} }

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
			DetectorType: detectors.Hyperline,
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

// nearKeyword reports whether a `hyperline[_-]?(api)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict precedence) so a key defined
// alongside a nearby HYPERLINE_API_KEY reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/customers?limit=1", nil)
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
