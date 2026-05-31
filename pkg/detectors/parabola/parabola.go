// Package parabola detects Parabola workflow API tokens — long alnum
// strings near a `parabola` keyword. Verified via /v2/user on
// api.parabola.io with an Authorization Bearer <TOKEN> header.
//
// No authoritative source pins Parabola's own API-credential prefix,
// length, or charset: trufflehog ships no parabola detector and Parabola's
// published docs only describe how Parabola authenticates *to* third-party
// APIs, not the shape of its own keys. We therefore keep the broad
// `[A-Za-z0-9]{32,80}` token shape (pinning a length would silently destroy
// recall) and apply recall-safe gate-tightening only: a `parabola`
// assignment-anchor reference within a tight 64-byte window, plus a
// conservative Shannon-entropy floor to drop structured low-information
// runs that clear the alnum regex.
package parabola

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.parabola.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No documented prefix to anchor on, so the keyword gate plus the entropy
// floor carry the false-positive load. Length stays unpinned (32..80) because
// no authoritative source documents Parabola's credential length.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,80})\b`)

// armRe is the assignment-style Parabola reference that must appear within the
// proximity window. A bare "parabola" substring (URLs, package names, prose)
// is too weak; `parabola_token` / `parabola-api-key` / `parabolasecret` is the
// shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)parabola[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 32..80-char runs that clear the alnum regex
// but are not random tokens (e.g. structured identifiers, padded names). 3.0
// is conservative: it culls obviously structured runs without over-tightening
// recall when the true credential charset is undocumented.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Parabola }

func (Scanner) Keywords() []string { return []string{"parabola"} }

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
		// Entropy gate: structured/low-information runs (e.g. a dotted
		// identifier or padded name) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Parabola,
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

// nearKeyword reports whether a `parabola[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby PARABOLA_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/user", nil)
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
