// Package ai21labs detects AI21 Labs API keys — long alphanumerics near
// the `ai21` keyword. Verified via /studio/v1/tokenize on api.ai21.com
// with Bearer auth.
package ai21labs

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.ai21.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy is a conservative floor. AI21 does not publish a key format
// (no prefix, length, or charset is documented anywhere authoritative — not
// in the auth docs, the dashboard, the Python SDK, nor any upstream
// trufflehog detector), so per the inconclusive-research fallback we do NOT
// pin a length and use the recall-safe 3.0 threshold rather than 3.5.
const minEntropy = 3.0

// armRe replaces the former bare strings.Contains(window,"ai21") gate. The
// bare substring matched any incidental "ai21" mention (and is kept in
// Keywords() as the prefilter); this assignment-style anchor requires the
// match to look like an AI21 credential reference within the window.
var armRe = regexp.MustCompile(`(?i)ai21[_\-]?(labs[_\-]?)?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AI21Labs }

func (Scanner) Keywords() []string { return []string{"ai21"} }

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
		// Entropy gate rejects low-information runs (repeated chars, padded
		// constants) that clear the regex but cannot be real key material.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AI21Labs,
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
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/studio/v1/tokenize", strings.NewReader(`{"text":"hi"}`))
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
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
