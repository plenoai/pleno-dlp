// Package scoutapm detects Scout APM agent credentials — a paired detector
// surfacing both the account-key (8-16 alphanumeric agent key) and the API
// key (>=40 base64url) near the `scoutapm` / `scout_apm` keyword. Verified
// via /api/v0/check on scoutapm.com using HTTP Basic auth (key as user,
// agent_key as password). Raw carries the agent key, RawV2 carries the API
// key.
package scoutapm

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://scoutapm.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Scout's organization/agent key ("key" in scout_apm.yml, SCOUT_KEY env) is a
// prefixless alphanumeric string. Official agent examples are inconsistent on
// length — the Ruby standalone example uses a 20-char placeholder
// (`00000000000000000000`) while the Laravel README uses a 21-char one
// (`ABC0ZABCDEFGHIJKLMNOP`) — and no Scout doc pins a canonical length or
// charset, so we do NOT hard-pin a length: the range below stays permissive
// enough to cover both documented shapes (and the historical fixture) and the
// FP load is carried by the arm-regex keyword gate + entropy floor, not the
// length. The API key (X-SCOUT-API header / `key` query arg) has no documented
// format at all, so it keeps a wide base64url range.
var agentKeyRe = regexp.MustCompile(`\b([A-Za-z0-9]{16,30})\b`)
var apiKeyRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,128})\b`)

// minEntropy rejects degenerate runs that clear the length regex but are not
// real keys — e.g. the all-zeros (`00000000000000000000`, entropy 0.0) and
// repeated-character placeholders that appear constantly in config templates.
// 3.0 is conservative: alnum keys of this length sit well above it (the 21-char
// Laravel example is 4.1, the 16-char fixture is 4.0), so recall is preserved
// while constant/structured fillers are culled. No prefix exists to anchor on,
// so the entropy floor plus the arm-regex gate together do the disambiguation.
const minEntropy = 3.0

// armRe is the assignment-style Scout reference that must appear within the
// proximity window. A bare "scoutapm" substring (script-src URLs, dependency
// names, doc prose) is too weak; a real key assignment or config key takes the
// `scout[…](agent|api…)?(key|token|secret)` shape — covering `SCOUT_KEY`,
// `scout_apm_agent_key`, `scoutapm_api_key`, `scout-apm-token`, etc. The
// optional `apm`/`agent`/`api` segments are what distinguish an assignment from
// the bare vendor word.
var armRe = regexp.MustCompile(`(?i)scout[_-]?(apm)?[_-]?(agent[_-]?)?(api[_-]?)?(key|token|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ScoutAPM }

func (Scanner) Keywords() []string { return []string{"scoutapm", "scout_apm"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	akHits := agentKeyRe.FindAllSubmatchIndex(data, -1)
	apiHits := apiKeyRe.FindAllSubmatchIndex(data, -1)
	if len(akHits) == 0 || len(apiHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, ak := range akHits {
		agentKey := string(data[ak[2]:ak[3]])
		if _, dup := seen[agentKey]; dup {
			continue
		}
		if !detectors.HasMinEntropy(agentKey, minEntropy) {
			continue
		}
		if !nearKeyword(lower, ak[2], ak[3]) {
			continue
		}
		var apiKey string
		for _, ah := range apiHits {
			cand := string(data[ah[2]:ah[3]])
			if cand == agentKey || len(cand) <= 16 {
				continue
			}
			if !detectors.HasMinEntropy(cand, minEntropy) {
				continue
			}
			if !nearKeyword(lower, ah[2], ah[3]) {
				continue
			}
			apiKey = cand
			break
		}
		if apiKey == "" {
			continue
		}
		seen[agentKey] = struct{}{}
		seen[apiKey] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ScoutAPM,
			Raw:          []byte(agentKey),
			RawV2:        []byte(apiKey),
			Redacted:     redact(agentKey),
		}
		if verify {
			v, err := s.Verify(ctx, agentKey+":"+apiKey)
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

// nearKeyword reports whether a `scout…key/token/secret` assignment-style
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby SCOUT_KEY / scout_apm.yml `key:` reference still
// arms. Radius is 64 (was 256): the prefixless alnum shape is far too common
// to justify a wide window.
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

// Verify accepts the combined `agentKey:apiKey` pair.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	agentKey, apiKey := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v0/check", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(apiKey, agentKey)
	req.Header.Set("Accept", "application/json")
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
