// Package sentinelone detects SentinelOne Singularity API tokens —
// long alphanumerics near the `sentinelone` or `s1` keyword.
// Unverified-by-default; the per-management-console host
// (`<console>.sentinelone.net`) isn't in the chunk. Verify only fires
// when an apiBase override is supplied.
package sentinelone

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{80,256})\b`)

// armRe is the assignment-style SentinelOne reference that must appear within
// the proximity window. SentinelOne does not publicly document the API token's
// length or charset (NinjaOne, Stitchflow, Sumo Logic integration guides all
// describe only the `Authorization: ApiToken <token>` scheme), so the token
// length stays at the conservative {80,256} and recall rests on the gate.
// A bare "sentinelone" substring (doc links, the per-console
// `<console>.sentinelone.net` host) is too weak a gate against a generic
// 80-256 alphanumeric run; `sentinelone[_-]?(api[_-]?)?(token|key|secret)` is
// the shape a real credential assignment or config key takes. The bare
// keyword is kept in Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)sentinelone[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 80-256 char runs that clear the alnum regex
// but are not random tokens (padded placeholders, long repeated-character
// runs). 3.0 is conservative — chosen to preserve recall absent a documented
// charset, since a tighter floor would silently cull real tokens.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SentinelOne }

func (Scanner) Keywords() []string { return []string{"sentinelone"} }

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
		// Entropy gate: structured/low-information 80-256 char runs (a padded
		// placeholder or a long run of repeated characters) clear the alnum
		// regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.SentinelOne,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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
// `sentinelone[_-]?(api[_-]?)?(token|key|secret)` reference appears within a
// tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a credential defined
// alongside a nearby SENTINELONE_API_TOKEN reference still arms.
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
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/web/api/v2.1/system/info", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "ApiToken "+secret)
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
