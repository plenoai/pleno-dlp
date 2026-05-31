// Package mistral detects Mistral AI API keys (32-char base62) and verifies
// them against /v1/models.
//
// Mistral keys do not carry a public prefix — the dashboard issues a 32-char
// base62 string. The keyword gate ("mistral" / env names) is mandatory
// because the shape collides with many opaque tokens.
package mistral

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mistral.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// keyRe matches a 32-char base62 run. NOTE: Mistral does not publish an
// authoritative API-key format (no prefix, length, or charset is documented
// in the official docs, and trufflehog ships no mistral detector to mirror).
// The 32-char length here is the pre-existing heuristic, NOT a documented
// value — it is retained as-is to preserve recall, not tightened on a guess.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minEntropy is a conservative floor. Without a documented charset we cannot
// assume key-grade randomness, so 3.0 (not 3.5) is used to cull only the
// clearly-structured runs (repeated/low-variety 32-char strings) that clear
// the regex while leaving genuine high-entropy keys untouched.
const minEntropy = 3.0

// armRe is the assignment-anchored keyword gate. A bare strings.Contains over
// the window matched English prose containing "mistral"; this arm regex keeps
// the assignment-style fixtures (mistral_api_key=, MISTRAL_KEY:, etc.) armed
// while rejecting incidental mentions. The bare "mistral" keyword stays in
// Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)mistral[_-]?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mistral }

func (Scanner) Keywords() []string { return []string{"mistral"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
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
		// Entropy gate: repeated / low-variety 32-char runs clear the bare
		// regex but lack key-grade randomness. Rejected before the keyword gate.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Mistral,
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
	return armRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/models", nil)
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
