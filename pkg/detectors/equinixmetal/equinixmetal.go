// Package equinixmetal detects Equinix Metal (formerly Packet) API tokens —
// 32-char alnum tokens near `equinix` / `packet` / `metal_api` keywords.
// Verified via /metal/v1/user on api.equinix.com using the X-Auth-Token header.
package equinixmetal

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.equinix.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Equinix Metal API tokens are 32-char alnum.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minEntropy gates out low-information 32-char runs (repeated chars, padded
// identifiers) that clear the length floor but are not tokens. 3.0 is chosen
// deliberately over 3.5: real Equinix tokens are frequently hex-style, whose
// entropy ceiling is ~4.0 and which in practice cap around ~3.6 — a 3.5 floor
// over-culls those legitimate tokens.
const minEntropy = 3.0

// anchorRe matches the assignment-style references that must appear near a
// token. A bare `equinix` substring (e.g. a docs URL or marketing copy) no
// longer arms a token — only anchored credential shapes do. `equinix` is kept
// in Keywords() as a cheap prefilter, but the proximity gate is stricter.
var anchorRe = regexp.MustCompile(`metal_api|packet_api|metal_token|equinix[_\-]?(?:api|token|metal)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.EquinixMetal }

func (Scanner) Keywords() []string { return []string{"equinix", "metal_api", "packet"} }

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
		// Entropy gate: structured/repeated 32-char runs are rejected.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.EquinixMetal,
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

// nearKeyword reports whether an anchored credential reference appears within
// a tight window around the token. The radius is 96 bytes (down from 256) and
// a bare `equinix` substring no longer arms — only anchorRe shapes do.
func nearKeyword(lower string, start, end int) bool {
	const radius = 96
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return anchorRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/metal/v1/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Auth-Token", secret)
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
