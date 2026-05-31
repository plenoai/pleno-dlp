// Package box detects Box developer tokens (32+ char alnum) gated on the
// `box_developer` / `box_token` keyword window. Verified via /2.0/users/me
// against api.box.com with Bearer auth — that endpoint returns the
// authenticated user and is read-only safe.
package box

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.box.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Box developer/access tokens are 32-char alnum strings with no public
// prefix — matching upstream trufflehog
// (pkg/detectors/box: `\b([0-9a-zA-Z]{32})\b`). The length is pinned to the
// documented 32 rather than a {32,64} range; widening it past the
// authoritative shape only invents recall the format does not support.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minEntropy rejects 32-char low-information runs (padded hex, repeated
// patterns) that clear the alnum regex but lack key-grade randomness. 3.5 is
// the high-variety-charset floor from docs/detector-key-formats.md.
const minEntropy = 3.5

// contextRe is the windowed assignment-anchor gate. It replaces the previous
// bare strings.Contains over the keyword list, which fired on any prose
// mention of "box.com". The arm regex requires a box token/key/secret
// assignment-style identifier near the candidate.
var contextRe = regexp.MustCompile(`(?i)box[_-]?(developer[_-]?)?(api[_-]?)?(access[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Box }

// "box" is too short and ambiguous to be a useful prefilter on its own —
// gate the chunk on the more specific "box_" prefix that engineers use in
// configuration.
func (Scanner) Keywords() []string { return []string{"box_"} }

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
		// Entropy gate: structured 32-char runs that clear the alnum regex but
		// lack key-grade randomness are rejected.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Box,
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
