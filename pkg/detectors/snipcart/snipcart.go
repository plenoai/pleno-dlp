// Package snipcart detects Snipcart secret API keys. Per the upstream
// trufflehog detector (pkg/detectors/snipcart), a Snipcart secret key is
// exactly 75 chars of [0-9A-Za-z_] with no distinguishing prefix — a generic
// high-variety shape — so a bare "snipcart" substring within a wide window is
// too loose a gate. We require a `snipcart[_-]?(api[_-]?)?(token|key|secret)`
// reference within a tight 64-byte window AND a Shannon-entropy floor before
// surfacing. Verified via /api/orders on app.snipcart.com using HTTP Basic
// auth (key as username, empty password — the trailing `:` is significant).
package snipcart

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.snipcart.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Exactly 75 chars of [0-9A-Za-z_], per the upstream trufflehog detector
// (`\b([0-9A-Za-z_]{75})\b`). No prefix to anchor on, so the keyword arm
// regex + entropy floor carry the false-positive load.
var tokenRe = regexp.MustCompile(`\b([0-9A-Za-z_]{75})\b`)

// armRe is the assignment-style Snipcart reference that must appear within the
// proximity window. A bare "snipcart" substring (script-src URLs, package
// names, comments) is too weak; the shape a real secret-key assignment or
// config key takes is `snipcart_api_key` / `snipcart-secret` / "snipcart token".
var armRe = regexp.MustCompile(`(?i)snipcart[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 75-char runs that clear the charset regex but
// are not random keys (e.g. structured identifiers, repeated padding).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Snipcart }

func (Scanner) Keywords() []string { return []string{"snipcart"} }

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
		// Entropy gate: structured/low-information 75-char runs (padded names,
		// repeated identifiers) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Snipcart,
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

// nearKeyword reports whether a `snipcart[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby SNIPCART_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/orders", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
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
