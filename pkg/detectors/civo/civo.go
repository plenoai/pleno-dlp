// Package civo detects Civo Cloud API keys (50-char base62 near an armed
// `civo[_-]?(api[_-]?)?(token|key|secret)` reference, entropy >= 3.0).
// Verified via /v2/account on api.civo.com using `Authorization: Bearer <key>`.
package civo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.civo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Civo API keys are mixed-case base62 with no prefix. No authoritative source
// pins an exact length/charset: the civo/cli README example is 50 chars
// (DAb75oyqVeaE7BI6Aa74FaRSP0E2tMZXkDWLC9wNQdcpGfH51r) while civogo unit-test
// fixtures use 32-hex values — the two disagree, so the length is NOT
// authoritatively documented. We therefore keep the existing {50} match
// (changing it could destroy recall in either direction) and rely on the armed
// keyword gate plus a conservative entropy floor to suppress false positives.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{50})\b`)

// armRe is the assignment-style Civo reference that must appear within the
// proximity window. A bare "civo" substring (dependency names, civo CLI prose,
// hostnames like civo.com) is too weak; "civo_api_key" / "civo-token" /
// "civosecret" is the shape a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)civo[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 50-char runs that clear the alnum regex
// but are not random tokens (padded identifiers, repeated chars). Conservative
// 3.0 floor because the charset/length is not authoritatively documented; a
// real base62 key clears ~5.3 bits/char.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Civo }

func (Scanner) Keywords() []string { return []string{"civo"} }

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
		// An armed `civo[_-]?(api[_-]?)?(token|key|secret)` reference within a
		// tight window is mandatory — 50-char alphanumerics are not rare.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 50-char runs are rejected
		// even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Civo,
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

// nearKeyword reports whether an armed Civo reference appears within a tight
// window on either side of the token. The window spans both directions so a
// token defined alongside a nearby civo_api_key reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/account", nil)
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
