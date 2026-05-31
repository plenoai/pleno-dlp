// Package kayako detects Kayako support API tokens — long alnum
// strings near a `kayako` keyword. Verified via /api/v1/me on
// kayako.com with X-Auth-Token header.
package kayako

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://kayako.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Kayako reference that must appear within the
// proximity window. Kayako does not publish a fixed length or charset for its
// API token (the email+token auth path verified here): the official auth docs
// only show variable-length alphanumeric examples (60-80 chars) and a separate
// UUID-shaped OAuth token, so the token regex cannot be tightened by format
// without destroying recall. A bare "kayako" substring (doc links, the
// kayako.com host, blog URLs) is too weak a gate against a generic 40-80 alnum
// run; `kayako[_-]?(api[_-]?)?(token|key|secret)` is the shape a real
// credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)kayako[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 40-80 char runs that clear the alnum regex but
// are not random tokens (padded placeholders, repeated characters). Kept
// conservative (3.0, not 3.5) because no authoritative source pins the charset,
// so a token drawn from a narrow alphabet must not be over-culled.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kayako }

func (Scanner) Keywords() []string { return []string{"kayako"} }

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
		// Entropy gate: structured/low-information 40-80 char runs (a padded
		// placeholder or a long run of repeated characters) clear the alnum
		// regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Kayako,
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

// nearKeyword reports whether a `kayako[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby KAYAKO_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Auth-Token", secret)
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
