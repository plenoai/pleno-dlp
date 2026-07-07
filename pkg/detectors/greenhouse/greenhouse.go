// The official Harvest API docs document the token as a 32-character
// lowercase hex string with no prefix (example <TOKEN> = a7183e1b…), so the
// regex is anchored to the hex charset rather than a bare alphanumeric run.
// Verified via /v1/users on harvest.greenhouse.io with HTTP Basic auth
// (key as username, blank password).
//
// Source: https://developers.greenhouse.io/harvest.html ("The username
// is your Greenhouse API token …") and the upstream API docs repo
// https://github.com/grnhse/greenhouse-api-docs/blob/master/source/includes/harvest/_introduction.md
// both show a 32-char hex example token.
package greenhouse

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://harvest.greenhouse.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches a lowercase-hex run of at least the documented 32-char
// length. The documented format is exactly 32 hex chars; the lower bound
// (not a fixed {32}) preserves recall for any longer hex-encoded variant
// while the hex charset already rejects the mixed-case alphanumeric noise
// the previous bare [A-Za-z0-9] pattern admitted.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32,})\b`)

// armRe is the assignment-style Greenhouse/Harvest reference that must
// appear within the proximity window. A bare "greenhouse"/"harvest"
// substring (doc links, the harvest.greenhouse.io host, marketing copy)
// is too weak a gate against a generic 32+ hex run. The arming shapes a
// real credential assignment or config key takes are
// `greenhouse_api(_key|_token|_secret)?`, `harvest_token`, etc. — note
// the bare `GREENHOUSE_API` env-var form (no token/key/secret suffix) is
// itself a credible anchor and must arm, so the suffix is optional after
// `api`.
var armRe = regexp.MustCompile(`(?i)(greenhouse|harvest)[_\-]?(api([_\-]?(token|key|secret))?|token|key|secret)`)

// minEntropy rejects low-entropy 32+ hex runs that clear the hex regex but
// are not random tokens (e.g. 00000…/deadbeef-style padded placeholders or
// repeated nibbles). Hex caps at ~4 bits/char and real 32-char hex tokens
// sit well above 3.0; 3.5 would over-cull legitimate hex keys, so the floor
// is the conservative 3.0 from the hex/low-variety rubric branch.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Greenhouse }

func (Scanner) Keywords() []string { return []string{"greenhouse"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Greenhouse,
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

// nearKeyword reports whether a
// `(greenhouse|harvest)[_-]?(api[_-]?)?(token|key|secret)` reference appears
// within a tight window on either side of the candidate. The window spans
// both directions (not strict immediate precedence) so a credential defined
// alongside a nearby GREENHOUSE_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")
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
