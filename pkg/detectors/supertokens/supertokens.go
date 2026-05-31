// Package supertokens detects SuperTokens core API keys near the
// `supertokens` keyword. Unverified-by-default; the per-deployment
// self-hosted core URL isn't in the chunk. Verify only fires when an
// apiBase override is supplied.
//
// Key format (authoritative): SuperTokens core api_keys are
// operator-chosen, not provider-issued — there is no distinguishing
// prefix and no fixed length. The canonical config documents the only
// constraints: "Keys can only contain '=', '-' and alpha-numeric
// (including capital) chars. Each key must have a minimum length of 20
// chars." (supertokens-core config.yaml). Because the upper bound is
// open and there is no prefix to anchor on, the candidate regex pins
// only the documented 20-char minimum + documented charset, and the
// false-positive load is carried by (1) a tight assignment-style arm
// regex within a 64-byte window and (2) a conservative Shannon-entropy
// floor. We deliberately do NOT pin a maximum length — that would
// silently destroy recall for longer operator-chosen keys.
package supertokens

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

// tokenRe matches the documented SuperTokens api_key charset (alphanumeric
// incl. capitals, '=', '-') at the documented 20-char minimum. No maximum is
// pinned — keys are operator-chosen with no documented upper bound — so the
// quantifier is open-ended ({20,}). '=' / '-' are not \b word chars, so the
// match is bounded by surrounding boundaries via the charset itself rather
// than \b on the symbol ends.
var tokenRe = regexp.MustCompile(`([A-Za-z0-9=\-]{20,})`)

// armRe is the assignment-style SuperTokens reference that must appear within
// the proximity window. A bare "supertokens" substring (npm dependency names,
// import paths, doc prose, script-src URLs) is too weak a gate for a
// prefix-less operator-chosen key; "supertokens_api_key" / "super-tokens-key"
// / "supertokenstoken" is the shape a real key assignment or config entry
// takes. The bare keyword stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)super[_\-]?tokens?[_\-]?(api[_\-]?)?(key|token|secret)`)

// minEntropy rejects low-information runs that clear the charset regex but are
// not random keys (padded identifiers, repeated chars). 3.0 is conservative:
// keys may be as short as 20 chars (less entropy headroom) and the documented
// example key clears 3.0 with margin, so a higher floor would risk culling
// real keys. The charset is high-variety but the recall-safe choice for an
// operator-chosen, open-length format is the lower floor.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Supertokens }

func (Scanner) Keywords() []string { return []string{"supertokens"} }

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
		// An assignment-style supertokens reference within a tight window is
		// mandatory — the candidate is prefix-less and operator-chosen.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: low-information runs that clear the charset regex
		// (padded identifiers, repeated chars) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Supertokens,
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

// nearKeyword reports whether an assignment-style supertokens reference (see
// armRe) appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby SUPERTOKENS_API_KEY reference still arms. Radius
// was tightened 256->64 to cut the false-positive surface of a prefix-less
// candidate.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/hello", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("api-key", secret)
	req.Header.Set("cdi-version", "3.0")
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
