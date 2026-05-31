// Package socure detects Socure RiskOS API keys near a `socure` keyword.
//
// Socure's authoritative authentication docs (help.socure.com RiskOS
// "API and SDK Keys" / "Customization") document the API key as a UUID v4 —
// the Bearer example shown is `a182150a-363a-4f4a-<UUID-V4-TOKEN>`, i.e. the
// 8-4-4-4-12 hex-with-hyphens layout with the version nibble `4` and the
// variant nibble in `[89ab]`. We anchor on that structure: a bare
// `[A-Za-z0-9]{40,80}` run (the previous regex) does not even match the real
// format and matches arbitrary high-entropy noise instead. Because the UUID
// layout (hyphen positions + version/variant nibbles) is itself a strong
// discriminator, no entropy floor is needed — per docs/detector-key-formats.md
// "distinguishing structure exists: anchor the regex; entropy unnecessary".
//
// The keyword gate is also tightened: a bare "socure" Contains over a 256-byte
// window is replaced by a `socure[_-]?(api[_-]?)?(token|key|secret)` arm regex
// within a 64-byte window, with the bare "socure" kept only as the engine
// prefilter (Keywords()).
//
// Verified via /api/3.0/devicedata/health on api.socure.com with the
// `Authorization: SocureApiKey <key>` header.
package socure

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.socure.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe anchors on the documented UUID v4 structure (8-4-4-4-12 hex, version
// nibble 4, variant nibble [89ab]). Source: help.socure.com RiskOS
// authentication docs. The structure is the discriminator, so no entropy gate.
var tokenRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})\b`)

// armRe is the assignment-style Socure reference that must appear within the
// proximity window. A bare "socure" substring (script-src URLs, dependency
// names, comments, docs links) is too weak; "socure_api_key" / "socure-token" /
// "socurekey" is the shape a real key assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)socure[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Socure }

// Keywords must include "socure" — without it the engine would have no gate at
// all and we'd evaluate the UUID regex against every chunk. It stays the cheap
// prefilter; armRe (above) carries the false-positive load.
func (Scanner) Keywords() []string { return []string{"socure"} }

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
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Socure,
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

// nearKeyword reports whether a `socure[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight 64-byte window on either side of the token.
// The window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby SOCURE_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/3.0/devicedata/health", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "SocureApiKey "+secret)
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
