// Package cohere detects Cohere API keys (40-char base62) and verifies them
// against /v1/check-api-key.
//
// Cohere keys do not carry a public prefix — the dashboard issues a 40-char
// base62 string with no "co_" identifier. The keyword gate ("cohere" / env
// names) is mandatory because the shape collides with many random secret
// formats.
package cohere

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.cohere.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 40 base62 chars. Generic shape — keyword gate disambiguates.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)

// minEntropy rejects git-SHA-shaped and other low-information 40-char runs
// that clear the regex but are not real keys.
const minEntropy = 3.5

// contextRe is the windowed keyword gate. A bare "cohere" substring matched
// English words like "coherent"/"coherence"; the word boundary kills those
// while the _api_key forms keep the assignment-style fixtures armed.
var contextRe = regexp.MustCompile(`(?i)\bcohere\b|co_api_key|cohere_api_key`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Cohere }

func (Scanner) Keywords() []string { return []string{"cohere"} }

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
		// Entropy gate: git-SHA-shaped 40-char hex and other structured runs
		// that clear the regex but lack key-grade randomness are rejected.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Cohere,
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
	const radius = 256
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v1/check-api-key", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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
