// Package deel detects Deel API tokens — 40+ char alphanumeric strings near a
// `deel`/`letsdeel` token-assignment reference, gated by a conservative entropy
// floor. Verified via /rest/v2/users/me on api.letsdeel.com with Bearer auth.
//
// Deel publishes no token prefix, length, or charset (the auth docs only show a
// `Bearer <TOKEN>` placeholder), so the regex stays broad and the proximity arm
// regex plus entropy floor carry the false-positive load.
package deel

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.letsdeel.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Deel does not publish a token prefix, length, or charset. The official auth
// docs only show a `Bearer YOUR-TOKEN-HERE` placeholder and trufflehog upstream
// has no deel detector, so we cannot pin a length without destroying recall.
// We keep the broad 40+ alnum match and lean on a tightened proximity gate plus
// a conservative entropy floor instead. See research record in the FP-hardening
// campaign notes.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,})\b`)

// armRe is the assignment-style Deel reference that must appear within the
// proximity window. A bare "deel" / "letsdeel" substring (e.g. the api.letsdeel.com
// host, dependency names, comments) is too weak; "deel_api_token" / "deel-key" /
// "letsdeel_secret" is the shape a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)(?:lets)?deel[_\-]?(?:api[_\-]?)?(?:token|key|secret)`)

// minEntropy rejects low-entropy 40+ alnum runs that clear the regex but are not
// random tokens (e.g. structured identifiers, hex hashes, padded names). Set to
// the conservative 3.0 floor because the documented charset is unknown — a
// higher floor would risk over-culling a real token of unknown composition.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Deel }

func (Scanner) Keywords() []string { return []string{"deel"} }

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
			DetectorType: detectors.Deel,
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

// nearKeyword reports whether a `(lets)deel[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight proximity window of the candidate match.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/rest/v2/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
