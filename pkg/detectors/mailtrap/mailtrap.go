// Package mailtrap detects Mailtrap API tokens — long alphanumeric strings
// near a `mailtrap_(api_)?token|key|secret` assignment reference. Mailtrap
// authenticates via the `Api-Token: <TOKEN>` request header. Verified via
// /api/accounts on mailtrap.io.
//
// Mailtrap publishes no authoritative token length/charset (docs use
// placeholders; no upstream trufflehog detector), so this detector applies only
// recall-safe gate-tightening: a tight assignment-anchor proximity window and a
// conservative entropy floor — no length pin that could silently drop real
// tokens.
package mailtrap

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://mailtrap.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Mailtrap publishes no authoritative token format: the docs document only the
// `Api-Token` / `Authorization: Bearer` headers and use placeholders
// (`<YOUR_API_TOKEN>`), and there is no upstream trufflehog detector. The only
// observable structural fact is that tokens are alphanumeric (the API exposes a
// `last_4_digits` property). Without a sourced length/charset we keep the broad
// alphanumeric shape and lean on the gate + a conservative entropy floor rather
// than guess a length pin (an over-tight pin would silently destroy recall).
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,80})\b`)

// armRe is the assignment-style Mailtrap reference that must appear within the
// proximity window. A bare "mailtrap" substring (script/doc URLs, the
// mailtrap.io host, brand mentions) is too weak a gate against a generic
// 32-80 char alphanumeric run; `mailtrap[_-]?(api[_-]?)?(token|key|secret)` is
// the shape a real credential assignment or config key takes. The bare
// "mailtrap" keyword stays in Keywords() as the cheap prefilter.
var armRe = regexp.MustCompile(`(?i)mailtrap[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32-80 char runs that clear the alnum regex
// but are not random tokens (padded placeholders, repeated characters). 3.0 is
// the conservative floor used when no authoritative length/charset is known, so
// it does not over-cull a potentially hex/low-variety real token.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mailtrap }

func (Scanner) Keywords() []string { return []string{"mailtrap"} }

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
		// Entropy gate: structured/low-information runs (padded placeholders,
		// repeated characters) clear the alnum regex but are not random tokens.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Mailtrap,
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

// nearKeyword reports whether a `mailtrap[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict precedence) so a credential defined
// alongside a nearby MAILTRAP_API_TOKEN reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/accounts", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Api-Token", secret)
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
