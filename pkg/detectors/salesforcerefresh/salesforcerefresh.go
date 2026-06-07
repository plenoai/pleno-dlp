// Package salesforcerefresh detects Salesforce OAuth refresh tokens
// (5Aep861... shape). Verification is unverified-by-design: the Salesforce
// token endpoint requires the org's instance URL plus the connected-app
// client_id and client_secret — none of which are co-located with the token
// in the matched chunk (classify b, per docs/verify-coverage.md).
//
// Even unverified, a leaked refresh token is a real risk: anyone who obtains
// the matching connected-app credentials can mint access tokens. We surface
// the finding at Severity=Medium to acknowledge "definitely a refresh token,
// but verification of liveness is structurally impossible from the chunk alone".
package salesforcerefresh

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 5Aep861 is the well-known prefix Salesforce uses for refresh tokens issued
// against the standard "User-Agent OAuth" / "Web Server OAuth" flows. The
// tail is URL-safe base64-ish; we accept >=60 trailing chars to filter
// truncated samples.
var tokenRe = regexp.MustCompile(`\b(5Aep861[A-Za-z0-9._-]{60,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SalesforceRefresh }

func (Scanner) Keywords() []string { return []string{"5Aep861"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		// Verify is intentionally skipped — see package doc. Severity is set
		// explicitly so the engine's DefaultSeverity (which would say High
		// for unverified explicit detectors) doesn't overstate confidence.
		out = append(out, detectors.Result{
			DetectorType: detectors.SalesforceRefresh,
			Severity:     detectors.SeverityMedium,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
}

func redact(t string) string {
	// "5Aep861" prefix + 4 chars after = 11 chars shown, rest hidden.
	if len(t) <= 11 {
		return t
	}
	return t[:11] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
