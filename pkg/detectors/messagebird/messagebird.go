// Package messagebird detects MessageBird API access keys gated on a
// `messagebird` reference. The access-key body is a fixed 25-character
// high-variety run (the body of an optionally `test_`-prefixed key, e.g.
// the docs example `test_<25-CHAR-BODY>`); live keys carry no prefix, so
// there is no distinguishing anchor and the keyword gate plus an entropy
// floor carry the false-positive load. Length and charset are pinned to
// trufflehog's upstream detector (`[A-Za-z0-9_-]{25}`), which agrees with
// MessageBird's documented key example. Verified via /contacts on
// rest.messagebird.com with `Authorization: AccessKey <TOKEN>` — that is
// MessageBird's idiomatic auth header, distinct from Bearer.
package messagebird

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://rest.messagebird.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Exactly 25 chars over [A-Za-z0-9_-], pinned to trufflehog upstream
// (pkg/detectors/messagebird) and consistent with the documented key body.
// No prefix to anchor on, so the keyword gate and entropy floor carry the
// false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{25})\b`)

// armRe is the assignment-style MessageBird reference that must appear within
// the proximity window. A bare "messagebird" substring (doc links, the
// messagebird.com host, dependency names) is too weak a gate against a generic
// 25-char run; `messagebird[_-]?(api[_-]?)?(access[_-]?)?(token|key|secret)`
// is the shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)messagebird[_\-]?(api[_\-]?)?(access[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 25-char runs that clear the charset regex but
// are not random tokens (e.g. structured identifiers, padded names). The body
// is high-variety alphanumeric, so 3.5 is safe without over-culling.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MessageBird }

func (Scanner) Keywords() []string { return []string{"messagebird"} }

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
		// Entropy gate: structured/low-information 25-char runs (e.g. a
		// dotted identifier or padded name) clear the charset regex but are
		// not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.MessageBird,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/contacts?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "AccessKey "+secret)
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

// nearKeyword reports whether a messagebird credential reference (per armRe)
// appears within a tight window on either side of the candidate. The window
// spans both directions (not strict immediate precedence) so a key defined
// alongside a nearby MESSAGEBIRD_ACCESS_KEY reference still arms.
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
