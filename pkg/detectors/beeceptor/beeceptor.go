// Package beeceptor detects Beeceptor HTTP mock API keys. Verified via
// /api/v1/projects on app.beeceptor.com with an Authorization Bearer header.
//
// Key format (authoritative): the official Beeceptor API docs document the
// API key as a lowercase-hex string, exemplified as
// `14ac5499cfdd2bb2859e4476d2e5b1d2bad079bf` (40 hex chars) — see
// https://beeceptor.com/docs/api-overview/. There is no distinguishing prefix.
//
// Hardening (FP campaign): the prior regex was a bare `[A-Za-z0-9]{32,}` with a
// radius-256 bare-`strings.Contains("beeceptor")` gate and no entropy floor — it
// armed on any long mixed-case alnum run (base64 blobs, JWT segments, nonces)
// that merely shared a chunk with the word "beeceptor". We now (1) constrain the
// charset to hex to match the documented format, killing the large class of
// non-hex high-entropy false positives; (2) keep the documented-format-consistent
// `{32,}` lower bound rather than pinning an exact length, because the hex
// branch of docs/detector-key-formats.md warns that length-pinning hex silently
// destroys recall; (3) add HasMinEntropy(token, 3.0) — hex entropy caps ~3.6, so
// 3.0 (not 3.5) is the recall-safe floor for low-variety charsets; and (4)
// replace the bare keyword Contains over radius 256 with an assignment-anchor arm
// regex within radius 64, retaining the bare "beeceptor" keyword as the engine
// prefilter.
package beeceptor

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.beeceptor.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Lowercase/uppercase hex, length >= 32. The documented key is 40 hex chars
// (https://beeceptor.com/docs/api-overview/); we keep a >=32 lower bound rather
// than pinning 40 because the hex branch of the key-format playbook treats hex
// length-pinning as recall-hostile.
var tokenRe = regexp.MustCompile(`\b([a-fA-F0-9]{32,})\b`)

// armRe is the assignment-style Beeceptor reference that must appear within the
// proximity window. A bare "beeceptor" substring (mock-server URLs, package
// names, prose) is too weak to gate a generic hex run; the
// `beeceptor[_-]?(api[_-]?)?(token|key|secret)` shape is what a real credential
// assignment or config key looks like.
var armRe = regexp.MustCompile(`(?i)beeceptor[_-]?(api[_-]?)?(token|key|secret)`)

// minEntropy rejects low-information hex runs (repeated/structured digits,
// padded identifiers) that clear the regex but lack key-grade randomness. Hex
// entropy caps near 3.6 bits/char, so 3.0 is the recall-safe floor; 3.5 would
// over-cull genuine keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Beeceptor }

func (Scanner) Keywords() []string { return []string{"beeceptor"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: low-information hex runs (repeated digits, structured
		// identifiers) clear the charset/length regex but are not real keys.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Beeceptor,
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

// nearKeyword reports whether an assignment-style Beeceptor reference appears
// within a tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a key defined alongside a
// nearby BEECEPTOR_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/projects", nil)
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
