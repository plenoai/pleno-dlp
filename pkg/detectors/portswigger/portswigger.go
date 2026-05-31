// Package portswigger detects PortSwigger Burp Suite Enterprise API
// keys — long alnum strings near a `portswigger` or `burp` keyword.
// Verified via /api/v1/sites on burp host with Authorization header.
package portswigger

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://burpsuite.example.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style PortSwigger/Burp reference that must appear
// within the proximity window. A bare "portswigger"/"burp" substring (doc
// links, vendor mentions, the `burpsuite.example.com` host) is too weak a gate
// against a generic 40-80 alphanumeric run. PortSwigger does not publish an
// authoritative prefix/length/charset for the Burp Suite Enterprise (DAST) API
// key — the docs only place it in the URL path (`/api/<TOKEN>/...`) — so the
// length cannot be safely pinned. We arm on the credential-assignment shape
// `(portswigger|burp)[_-]?(api[_-]?)?(token|key|secret)` instead. The bare
// "portswigger"/"burp" prefilter stays in Keywords() to gate the engine.
var armRe = regexp.MustCompile(`(?i)(portswigger|burp)[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-80 char runs that clear the alnum regex
// but are not random tokens (padded placeholders, repeated characters). 3.0 is
// the conservative floor for an unknown charset: it culls obvious filler
// without risking recall on a real key whose alphabet is undocumented.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PortSwigger }

func (Scanner) Keywords() []string { return []string{"portswigger", "burp"} }

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
		// Entropy gate: structured/low-information 40-80 char runs (padded
		// placeholders, long repeated-character runs) clear the alnum regex
		// but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.PortSwigger,
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

// nearKeyword reports whether an assignment-style PortSwigger/Burp credential
// reference (see armRe) appears within a tight window on either side of the
// candidate. The window spans both directions (not strict immediate
// precedence) so a key defined alongside a nearby PORTSWIGGER_API_KEY
// reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/"+secret+"/v0.1/sites", nil)
	if err != nil {
		return false, err
	}
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
