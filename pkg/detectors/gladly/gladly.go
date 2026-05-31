// Package gladly detects Gladly customer support agent_email +
// api_token pairs near the `gladly` keyword. Unverified-by-default;
// the per-org host (`<org>.gladly.com`) isn't in the chunk. Verify
// only fires when an apiBase override is supplied. Raw carries the
// email, RawV2 the token.
package gladly

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

var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

// armRe is the assignment-style Gladly reference that must appear within the
// proximity window. A bare "gladly" substring (script-src URLs, doc links,
// the per-org `<org>.gladly.com` host) is too weak a gate against a generic
// 32-128 alphanumeric run; `gladly[_-]?(api[_-]?)?(token|key|email)` is the
// shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)gladly[_\-]?(api[_\-]?)?(token|key|email)`)

// minEntropy rejects low-entropy 32-128 char runs that clear the alnum regex
// but are not random tokens (e.g. padded placeholders, repeated characters).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Gladly }

func (Scanner) Keywords() []string { return []string{"gladly"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	emails := emailRe.FindAllSubmatchIndex(data, -1)
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(emails) == 0 || len(tokens) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var email string
	for _, h := range emails {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		email = string(data[h[2]:h[3]])
		break
	}
	if email == "" {
		return nil, nil
	}
	var token string
	for _, h := range tokens {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == email {
			continue
		}
		// Entropy gate: structured/low-information 32-128 char runs (e.g. a
		// padded placeholder or a long run of repeated characters) clear the
		// alnum regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		token = v
		break
	}
	if token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Gladly,
		Raw:          []byte(email),
		RawV2:        []byte(token),
		Redacted:     redact(email),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, email+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a `gladly[_-]?(api[_-]?)?(token|key|email)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby GLADLY_API_TOKEN reference still arms.
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	email, token := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/agents/me", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(email, token)
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
