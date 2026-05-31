// Package aikidosecurity detects Aikido Security API tokens (40-char base62)
// gated on the `aikido` keyword window. Aikido tokens grant the issuing
// account's full code-scan + cloud-posture read scope, so verified hits
// surface SeverityCritical via engine default. Verification calls
// /api/public/v1/me on app.aikido.dev with Bearer auth.
package aikidosecurity

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.aikido.dev"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches a base62 run. Aikido's authoritative API docs
// (https://apidocs.aikido.dev/reference/getaccesstoken) document a two-part
// client_id/client_secret credential used via HTTP Basic auth, but do NOT
// publish a prefix, length, or charset for either half. With no authoritative
// format to pin, we keep the broad length window and lean on the armed keyword
// gate plus a conservative entropy floor to suppress false positives — pinning
// a guessed length here would silently destroy recall.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Aikido reference that must appear within the
// proximity window. A bare "aikido" substring (dependency names, doc prose,
// the company name in comments) is too weak; an
// `aikido[_-]?(api[_-]?)?(token|key|secret)` shape is what a real credential
// assignment or config key looks like.
var armRe = regexp.MustCompile(`(?i)aikido[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-80 char runs that clear the base62
// regex but are not random credentials (padded identifiers, repeated fillers).
// 3.0 is the conservative floor for the inconclusive-format case: high enough
// to drop structured strings, low enough to avoid culling real credentials of
// unknown charset distribution.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AikidoSecurity }

func (Scanner) Keywords() []string { return []string{"aikido"} }

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
		// Entropy gate: low-information 40-80 char runs (padded names,
		// repeated fillers) are rejected even when the keyword arms.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AikidoSecurity,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/public/v1/me", nil)
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
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

// nearKeyword reports whether an armed Aikido credential reference appears
// within a tight window on either side of the token. The radius is 64 (was
// 256): a real assignment keeps the key name adjacent to the value, and the
// wider window let unrelated base62 runs borrow a distant "aikido" mention.
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
