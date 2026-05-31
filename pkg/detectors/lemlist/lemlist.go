// Package lemlist detects Lemlist cold-email API user_email + api_key
// pairs near the `lemlist` keyword. Verified via /api/team on
// api.lemlist.com with HTTP Basic auth (user:api_key). Raw carries the
// email, RawV2 the api_key.
package lemlist

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lemlist.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)

// tokenRe matches the lemlist API key shape: a 32-char lowercase hex string.
// Length + charset mirror the upstream trufflehog detector
// (github.com/trufflesecurity/trufflehog pkg/detectors/lemlist:
// `\b([a-f0-9]{32})\b`). The previous bare `[A-Za-z0-9]{32,128}` was far too
// broad and matched any long alphanumeric run near the keyword.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

// armRe is the assignment-style lemlist reference that must appear within the
// proximity window. A bare "lemlist" substring (doc links, the api.lemlist.com
// host, marketing copy) is too weak a gate; `lemlist[_-]?(api[_-]?)?(token|
// key|secret)` is the shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)lemlist[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32-char hex runs that clear the regex but
// are not random tokens (e.g. all-zero padding, repeated nibbles). Hex caps
// around 3.6 bits/char, so 3.0 is the conservative floor (3.5 would over-cull).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lemlist }

func (Scanner) Keywords() []string { return []string{"lemlist"} }

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
		// Entropy gate: structured/low-information 32-char hex runs (e.g. an
		// all-zero or repeated-nibble placeholder) clear the regex but are not
		// random tokens — reject them even when armed.
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
		DetectorType: detectors.Lemlist,
		Raw:          []byte(email),
		RawV2:        []byte(token),
		Redacted:     redact(email),
	}
	if verify {
		v, err := s.Verify(ctx, email+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a `lemlist[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby LEMLIST_API_KEY reference still arms.
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	email, token := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/team", nil)
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
