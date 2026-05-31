// Package vercel detects Vercel API access tokens. Tokens are 24-char
// alphanumeric — a generic shape that hits constantly in real codebases
// (commit SHAs, nonces, k8s object names) — so a bare "vercel" substring
// within a wide window is far too loose a gate. We instead require a
// `vercel[_-]?token`-style reference within a tight 64-byte window of the
// candidate AND gate on Shannon entropy before surfacing it. The window is
// searched on both sides (not strict immediate precedence) so a token in a
// `.vercel/` config file with a nearby VERCEL_TOKEN reference still arms.
// Verify hits /v2/user with Bearer.
package vercel

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.vercel.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 24 alphanumeric. No prefix to anchor on, so the keyword gate carries the
// false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)

// armRe is the assignment-style Vercel reference that must appear within the
// proximity window. A bare "vercel" substring (script-src URLs, dependency
// names, comments) is too weak; "vercel_token" / "vercel-token" / "verceltoken"
// is the shape a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)vercel[_\-]?token`)

// minEntropy rejects low-entropy 24-char runs that clear the alnum regex but
// are not random tokens (e.g. structured identifiers, padded names).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vercel }

// Keywords must include "vercel" — without it the engine would have no
// gate at all and we'd evaluate the 24-char regex against every chunk.
func (Scanner) Keywords() []string { return []string{"vercel"} }

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
		// A `vercel[_-]?token` reference within a tight window is mandatory —
		// 24-char alphanumerics are common (commit shas, nonces, k8s names).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 24-char runs (e.g. a
		// dotted identifier or padded name) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Vercel,
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
	return out, nil
}

// nearKeyword reports whether a `vercel[_-]?token` reference appears within a
// tight window on either side of the token. The window spans both directions
// (not strict immediate precedence) so a token defined alongside a nearby
// VERCEL_TOKEN reference — e.g. in a `.vercel/` config file — still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/user", nil)
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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
