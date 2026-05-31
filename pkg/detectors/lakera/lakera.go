// Package lakera detects Lakera Guard LLM-security API keys (32-64
// alnum). Verified via /v1/prompt_injection on api.lakera.ai with the
// Authorization Bearer header.
//
// Format research (2026-06): no authoritative source pins the Lakera key
// prefix/length/charset. Lakera's official docs (docs.lakera.ai/docs/api,
// /docs/quickstart, /docs/platform) only show the placeholder
// `$LAKERA_GUARD_API_KEY` behind `Authorization: Bearer` and never an
// example key; there is no upstream trufflehog lakera detector to mirror
// (the pkg/detectors/lakera path 404s). A single search-engine snippet
// claimed an `sk_` prefix but could not be reproduced against any official
// page, so anchoring on `sk_` or pinning a length would be a guess that
// silently destroys recall. We therefore keep the documented-shape regex
// unchanged and apply only recall-safe gate-tightening: a tight 64-byte
// proximity window, an assignment-anchor arm regex instead of a bare
// substring, and a conservative Shannon-entropy floor of 3.0.
package lakera

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lakera.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-64 alnum. No authoritative prefix/length to anchor on, so the keyword
// gate plus the entropy floor carry the false-positive load. Length range
// left as-is because no source documents a fixed length.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Lakera reference that must appear within the
// proximity window. A bare "lakera" substring (script URLs, package names,
// prose) is too weak; `lakera[_-]?(api[_-]?)?(token|key|secret)` is the shape
// a real key assignment or config entry takes (e.g. LAKERA_API_KEY,
// LAKERA_GUARD_API_KEY, lakera-api-token).
var armRe = regexp.MustCompile(`(?i)lakera[_\-]?(guard[_\-]?)?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor. No documented charset/length means we
// cannot safely assume high-variety randomness, so 3.0 (not 3.5) only rejects
// clearly structured 32-64 char runs without over-culling real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lakera }

func (Scanner) Keywords() []string { return []string{"lakera"} }

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
		// Entropy gate: structured/low-information 32-64 char runs (padded
		// identifiers, repeated patterns) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// An assignment-anchor `lakera...key` reference within a tight window
		// is mandatory — the bare 32-64 alnum shape is otherwise ubiquitous.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Lakera,
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

// nearKeyword reports whether a `lakera...key` assignment-style reference
// appears within a tight window on either side of the token. The window spans
// both directions (not strict precedence) so a key defined alongside a nearby
// LAKERA_API_KEY reference still arms.
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
	body := bytes.NewBufferString(`{"input":"hello"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v1/prompt_injection", body)
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
