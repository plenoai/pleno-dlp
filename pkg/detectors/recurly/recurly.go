// Package recurly detects Recurly subscription billing API keys (32-char
// alphanumeric) near an assignment-style `recurly[_-]?(api[_-]?)?(token|key|
// secret)` reference. Verified via /sites on v3.recurly.com using HTTP Basic
// auth with the key as username.
//
// Key format is undocumented by Recurly (official docs/SDKs and the upstream
// trufflehog/gitleaks rule sets all omit length/prefix/charset), so the regex
// is intentionally not re-tightened on an unverified length; the precision gate
// is the arm regex + radius-64 proximity + conservative entropy floor.
package recurly

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://v3.recurly.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// armRe is the assignment-style Recurly reference that must appear within the
// proximity window. A bare "recurly" substring (script-src URLs, doc links,
// `*.recurly.com` hosts) is too weak a gate against a generic 32-char
// alphanumeric run; `recurly[_-]?(api[_-]?)?(token|key|secret)` is the shape a
// real credential assignment or config key takes. The bare keyword stays in
// Keywords() as the engine prefilter.
//
// NOTE: no authoritative Recurly source documents the private API key's length,
// prefix, or charset — the official docs, the recurly-client SDKs, and the
// upstream trufflehog/gitleaks rule sets all omit it. So the existing `{32}`
// length is left unchanged (not re-pinned on an unverified claim) and only the
// recall-safe gate is tightened here: arm regex + tighter radius + conservative
// entropy floor.
var armRe = regexp.MustCompile(`(?i)recurly[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32-char alnum runs that clear the regex but
// are not random tokens (padded placeholders, repeated characters, slugs). 3.0
// is conservative — the key charset is undocumented, so a hex key (caps ~3.6)
// must still pass; 3.5 would over-cull and silently destroy recall.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Recurly }

func (Scanner) Keywords() []string { return []string{"recurly"} }

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
			DetectorType: detectors.Recurly,
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

// nearKeyword reports whether a `recurly[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a credential
// defined alongside a nearby RECURLY_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/sites", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/vnd.recurly.v2021-02-25+json")
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
