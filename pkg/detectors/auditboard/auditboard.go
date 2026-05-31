// Package auditboard detects AuditBoard GRC API tokens. Tokens are
// alphanumeric and surface only when the `auditboard` keyword is in the
// same chunk. Verified via /api/v1/me on app.auditboard.com with the
// Authorization Bearer header.
package auditboard

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.auditboard.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style AuditBoard reference that must appear within
// the proximity window. A bare "auditboard" substring (the app.auditboard.com
// host, doc links, vendor names) is too weak a gate against a generic 32-64
// alphanumeric run; `auditboard[_-]?(api[_-]?)?(token|key|secret)` is the shape
// a real credential assignment or config key takes. No authoritative source
// pins the AuditBoard token prefix/length/charset (trufflehog has no such
// detector; the developer portal is behind an auth wall; the public Analytics
// API docs document only that it is a "Bearer" token), so the length stays
// unpinned and the gate-tightening is recall-safe.
var armRe = regexp.MustCompile(`(?i)auditboard[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 32-64 char runs that clear the alnum regex but
// are not random tokens (padded placeholders, repeated characters). Held at a
// conservative 3.0 because the documented charset is unknown — a higher floor
// risks culling real lower-variety tokens and silently destroying recall.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AuditBoard }

func (Scanner) Keywords() []string { return []string{"auditboard"} }

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
			DetectorType: detectors.AuditBoard,
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

// nearKeyword reports whether an
// `auditboard[_-]?(api[_-]?)?(token|key|secret)` reference appears within a
// tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a credential defined
// alongside a nearby AUDITBOARD_API_TOKEN reference still arms.
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
