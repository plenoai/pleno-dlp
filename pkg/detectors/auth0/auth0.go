// Package auth0 detects Auth0 management API tokens (long JWT-shaped strings)
// when an "auth0" keyword sits in the same chunk window.
//
// This detector overlaps with the generic JWT detector: every Auth0 token IS
// a JWT. The keyword gate makes this detector additive — Auth0 hits are
// surfaced as Auth0 (with provider context) when they're identifiable as
// such, and the generic JWT detector keeps surfacing all other JWTs.
//
// Verify is intentionally not implemented. Auth0 management API tokens are
// audience-bound — the verification path lives at
// `https://<tenant>.auth0.com/api/v2/users` and the tenant slug is rarely in
// scope. We mark the leak unverified-by-design so operators rotate.
package auth0

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// JWT shape; same regex as the generic JWT detector. The keyword gate is
// what distinguishes this from a generic JWT hit.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

var contextKeywords = []string{"auth0", "auth0_token", "auth0_management"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Auth0 }

// "auth0" is the prefilter; the JWT shape always contains "eyJ" so the
// keyword carries the additive signal.
func (Scanner) Keywords() []string { return []string{"auth0"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := jwtRe.FindAllSubmatchIndex(data, -1)
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
		// Co-occurrence with "auth0" is mandatory; otherwise this would
		// duplicate every JWT detector hit.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Auth0,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Critical because management-API tokens grant tenant admin
			// scope. Verified=false because audience is not extractable.
			Severity: detectors.SeverityCritical,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
