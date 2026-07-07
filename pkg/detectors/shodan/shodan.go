// Package shodan detects Shodan API keys and verifies them via /api-info.
//
// Format (authoritative): the Shodan API key is a fixed 32-character key over
// the 62-char alphanumeric charset [a-zA-Z0-9] with no distinguishing prefix.
// This matches the upstream trufflehog detector
// (github.com/trufflesecurity/trufflehog, pkg/detectors/shodankey/shodankey.go),
// whose pattern is PrefixRegex(["shodan"]) + `\b([a-zA-Z0-9]{32})\b`.
//
// A bare 32-char alphanumeric run is extremely common (git SHAs are 40 hex,
// but MD5 hex, base62 ids, nonces, k8s object names routinely produce 32-char
// alnum runs), so the regex alone is pure noise. With no prefix to anchor on,
// precision comes from (1) an assignment-style `shodan...key`-shaped reference
// within a tight 64-byte window and (2) a Shannon-entropy floor that rejects
// structured low-information 32-char runs. Verify hits /api-info.
package shodan

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.shodan.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-char alphanumeric, per the documented Shodan key format (see package doc).
// The length is pinned from an authoritative source; the shape is too generic
// on its own to surface, so the arm regex + entropy floor carry the precision.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// armRe is the assignment-style Shodan reference that must appear within the
// proximity window. A bare "shodan" substring (the CLI name, dependency names,
// doc URLs, comments) is too weak; `shodan_api_key` / `shodan-token` /
// `shodanapikey` / `shodan secret` is the shape a real key assignment or
// config key takes.
var armRe = regexp.MustCompile(`(?i)shodan[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32-char runs that clear the alnum regex
// but are not random keys (padded identifiers, repeated-char strings). 3.5 is
// the standard floor for a high-variety (62-char) fixed-length token; a real
// 32-char Shodan key sits near 4.7-5.0 bits/char.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Shodan }

func (Scanner) Keywords() []string { return []string{"shodan"} }

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
		// A `shodan...key`-shaped reference within a tight window is mandatory —
		// 32-char alphanumerics are common (hex digests, base62 ids, nonces).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 32-char runs (e.g. a padded
		// identifier or repeated-char string) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Shodan,
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

// nearKeyword reports whether a `shodan...key`-shaped reference appears within
// a tight window on either side of the token. The window spans both
// directions, so a key defined alongside a nearby SHODAN_API_KEY reference
// still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api-info?key="+secret, nil)
	if err != nil {
		return false, err
	}
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
