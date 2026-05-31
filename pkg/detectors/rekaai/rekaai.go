// Package rekaai detects Reka AI API keys near the `reka` keyword.
// Verified via /v1/models on api.reka.ai with an X-Api-Key header.
package rekaai

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.reka.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Reka exposes no authoritative API-key format: docs.reka.ai and the
// official SDKs only ever show the placeholder "your-api-key" / the
// REKA_API_KEY env var, never a prefix, fixed length, or charset, and
// trufflehog ships no rekaai detector to mirror. We therefore do NOT
// pin a length or prefix (that would silently destroy recall) and keep
// the broad 32-64 alnum shape; false positives are bounded instead by a
// conservative entropy floor plus an assignment-anchored keyword gate.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy is the recall-safe conservative floor for an unsourced
// charset: 3.0 admits hex/low-variety key material (hex caps ~3.6) while
// culling repetitive low-information runs that clear the regex.
const minEntropy = 3.0

// armRe is the assignment-anchored keyword gate, evaluated within a tight
// radius. It replaces a bare strings.Contains(window, "reka") over a
// 256-char window — that matched prose like "Rekamilemu" and any unrelated
// secret sharing a chunk with the word. The bare "reka" prefilter still
// lives in Keywords().
var armRe = regexp.MustCompile(`(?i)reka(\.ai|ai)?[_-]?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RekaAI }

func (Scanner) Keywords() []string { return []string{"reka"} }

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
		// Conservative entropy floor: rejects repetitive low-information
		// runs that clear the broad regex but cannot be key material.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.RekaAI,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/models", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Api-Key", secret)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
