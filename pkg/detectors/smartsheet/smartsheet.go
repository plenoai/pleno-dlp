// Package smartsheet detects Smartsheet API access tokens (alnum, no public
// prefix) gated on the `smartsheet` keyword window. Verified via /2.0/users/me
// on api.smartsheet.com with Bearer auth — read-only and surfaces the
// authenticated user.
//
// Format research (2026-06): Smartsheet does NOT publish an authoritative
// fixed length or charset for raw API access tokens. The auth guide shows only
// an illustrative example (<TOKEN> ~38 alnum chars, no prefix); the length is
// not specified as a contract, and observed tokens vary. trufflehog has no
// smartsheet detector to mirror. Per the inconclusive-research fallback we do
// NOT pin a length and keep the wide {24,64} alnum range; instead we apply
// recall-safe gate-tightening only:
//   - radius shrunk 256 -> 64,
//   - the bare strings.Contains keyword gate replaced by an assignment-anchor
//     arm regex (the bare keyword stays in Keywords() as the prefilter),
//   - a conservative HasMinEntropy(token, 3.0) floor to drop low-information
//     runs that clear the loose alnum regex.
package smartsheet

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.smartsheet.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No documented prefix or fixed length; keep the wide alnum range and rely on
// the keyword gate + entropy floor to disambiguate.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,64})\b`)

// minEntropy rejects low-information runs that clear the loose alnum regex
// but are not tokens. 3.0 is the conservative hex-grade floor — high enough
// to drop garbage, low enough not to cull real alnum tokens (which sit well
// above 4.0 bits/char).
const minEntropy = 3.0

// contextRe is the windowed keyword gate. It replaces a bare
// strings.Contains(window, "smartsheet") scan: the assignment-anchor arm
// (smartsheet[_-]?(api[_-]?)?(token|key|secret)) keeps the env/config-style
// fixtures armed, while the bare \bsmartsheet\b match preserves recall for
// tokens introduced by a nearby plain "smartsheet" mention.
var contextRe = regexp.MustCompile(`(?i)smartsheet[_-]?(api[_-]?)?(token|key|secret)|\bsmartsheet\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Smartsheet }

func (Scanner) Keywords() []string { return []string{"smartsheet"} }

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
			DetectorType: detectors.Smartsheet,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/2.0/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
