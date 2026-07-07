// Package customerly detects Customerly customer-service API tokens —
// long alnum strings near a `customerly` keyword. Verified via
// /v1/account on api.customerly.io with Authorization Bearer header.
package customerly

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.customerly.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Customerly reference that must appear within
// the proximity window. The Customerly access-token format is not documented
// by an authoritative source (the official help-centre article describes only
// where to find the token, not its prefix/length/charset; trufflehog has no
// customerly detector), so the regex cannot be anchored on a prefix. A bare
// `customerly` substring is too weak a gate against a generic 40-80 char
// alphanumeric run; `customerly[_-]?(api[_-]?)?(token|key|secret)` is the
// shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)customerly[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 40-80 char runs that clear the alnum regex
// but are not random tokens (e.g. padded placeholders, repeated characters).
// 3.0 is conservative — recall-safe given the unknown documented charset.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Customerly }

func (Scanner) Keywords() []string { return []string{"customerly"} }

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
		// Entropy gate: structured/low-information 40-80 char runs (padded
		// placeholders, long repeated-character runs) clear the alnum regex
		// but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Customerly,
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

// nearKeyword reports whether a
// `customerly[_-]?(api[_-]?)?(token|key|secret)` reference appears within a
// tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a credential defined
// alongside a nearby CUSTOMERLY_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
