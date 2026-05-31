// Package inflection detects Inflection AI Pi API tokens — long alnum
// strings near the `inflection` keyword. Verified via /v1/chat on
// api.inflection.ai with Bearer auth.
package inflection

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.inflection.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe stays a generic alnum run: no authoritative source documents the
// Inflection key prefix/length/charset (developers.inflection.ai only shows a
// YOUR_API_KEY placeholder, and there is no upstream trufflehog detector to
// mirror). Pinning a length here would risk silently destroying recall, so the
// shape stays open and the keyword gate + entropy floor do the disambiguation.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,})\b`)

// minEntropy is a conservative floor (not the 3.5 high-variety value) because
// the documented charset is unknown; 3.0 rejects obvious low-information runs
// (repeated chars, structured IDs) without culling plausible key shapes.
const minEntropy = 3.0

// contextRe is the windowed assignment-anchor gate. It replaces a bare
// strings.Contains(window, "inflection") that matched any prose mentioning the
// word. The bare keyword stays in Keywords() as the engine prefilter.
var contextRe = regexp.MustCompile(`(?i)inflection[_-]?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Inflection }

func (Scanner) Keywords() []string { return []string{"inflection"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Inflection,
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
	return contextRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/models", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
