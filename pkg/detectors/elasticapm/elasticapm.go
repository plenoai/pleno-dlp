// Package elasticapm detects Elastic APM secret tokens — long alphanumerics
// gated by an `elastic[_-]?apm...(token|key|secret)` assignment reference within
// a tight window plus a conservative Shannon-entropy floor. The Elastic APM
// secret token has no authoritatively documented prefix, length, or charset:
// it is operator-defined (set in Fleet, or provisioned by Elastic Cloud), so we
// deliberately do NOT pin a length and apply only recall-safe gate-tightening.
// Verified via the per-deployment APM Server host with `Bearer <TOKEN>` auth.
// The deployment host isn't carried in the chunk so verify requires apiBase
// override and ships unverified-by-default.
package elasticapm

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase overrides the verify host. Default empty disables verify.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Elastic APM reference that must appear within
// the proximity window. The Elastic APM secret token is operator-defined
// freeform with no documented prefix, length, or charset (it is whatever the
// user sets in Fleet / Cloud provisions), so the token shape itself carries no
// distinguishing signal — a bare "elasticapm" substring (package names, doc
// URLs, comments) is too weak to gate on. We require the token-assignment shape
// `elastic[_-]?apm...token|secret` instead.
var armRe = regexp.MustCompile(`(?i)elastic[_\-]?apm[_\-]?(secret[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-80 char alnum runs that clear the regex
// but are not random tokens. Conservative 3.0 floor (not 3.5): the token charset
// is undocumented, so an over-tight floor would silently destroy recall.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ElasticAPM }

func (Scanner) Keywords() []string { return []string{"elastic-apm", "elasticapm", "elastic_apm"} }

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
		// Conservative entropy gate: a 40-80 char alnum run with low entropy
		// (padded identifiers, repeated structure) is not a random token.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ElasticAPM,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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

// nearKeyword reports whether an `elastic[_-]?apm...(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby ELASTIC_APM_SECRET_TOKEN reference still arms.
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/", nil)
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
