// Package bitwarden detects Bitwarden Secrets Manager (BWS) machine-
// account access tokens (`0.<uuid>.<base64>:<base64>` shape near
// `bitwarden` keyword).
//
// Verify is intentionally not implemented. Bitwarden's identity service
// rejects /accounts/prelogin probes for machine accounts, and the only
// authoritative validation is to mint a session and pull secrets — which
// is observable in audit logs. We surface the leak unverified-by-design
// and let reviewers rotate.
package bitwarden

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `0.` version + UUID + `.` + base64 access-key id + `:` + base64
// access-key secret. The version `0.` plus the colon separator is the
// distinctive shape; UUID + base64 segments confirm.
var tokenRe = regexp.MustCompile(`\b(0\.[a-f0-9-]{36}\.[A-Za-z0-9+/=_-]{20,}:[A-Za-z0-9+/=_-]{20,})\b`)

var contextKeywords = []string{"bitwarden", "bws", "bws_access", "secretsmanager"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bitwarden }

func (Scanner) Keywords() []string { return []string{"0."} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// `0.<uuid>.<base64>:<base64>` collides with arbitrary versioned
		// tokens; we require `bitwarden` co-occurrence to disambiguate.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Bitwarden,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Bitwarden machine-account tokens grant cross-org secrets
			// access; we surface SeverityCritical even unverified
			// because rotation is the only safe remediation.
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
