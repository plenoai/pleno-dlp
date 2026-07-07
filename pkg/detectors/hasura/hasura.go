// Package hasura detects Hasura Cloud admin secrets. A Hasura Cloud admin
// secret is a randomly generated 64-character alphanumeric string (matching
// upstream trufflehog's `[a-zA-Z0-9]{64}` pattern, the de-facto authoritative
// shape; Hasura does not separately publish a length/charset spec). It carries
// no distinguishing prefix, so a bare `hasura` substring over a wide window is
// far too loose a gate — 64-char alphanumerics also appear as hashes, build
// IDs, and nonces. We therefore (1) pin the length to the documented 64,
// (2) require a `hasura[_-]?(admin[_-]?)?secret`-style assignment reference
// within a tight 64-byte window, and (3) gate on Shannon entropy before
// surfacing the candidate.
//
// Verified via /v1/version on the per-project host (`<project>.hasura.app`)
// sending `x-hasura-admin-secret`. The project host isn't in the chunk so
// verify requires apiBase override and ships unverified-by-default.
package hasura

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`)

// armRe is the assignment-style Hasura admin-secret reference that must appear
// within the proximity window. A bare "hasura" substring is too weak; the
// shape a real secret assignment or env var takes is
// HASURA_GRAPHQL_ADMIN_SECRET / hasura-admin-secret / x-hasura-admin-secret.
// The `(graphql[_-]?)?(admin[_-]?)?secret` tail keeps the bare keyword in
// Keywords() as the prefilter while arming on the assignment context only.
var armRe = regexp.MustCompile(`(?i)hasura[_\-]?(graphql[_\-]?)?(admin[_\-]?)?secret`)

// minEntropy rejects low-entropy 64-char runs that clear the alnum regex but
// are not random secrets. The charset is high-variety so 3.5 bits/char is
// safe headroom.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Hasura }

func (Scanner) Keywords() []string { return []string{"hasura"} }

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
			DetectorType: detectors.Hasura,
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

// nearKeyword reports whether a `hasura...secret` assignment reference appears
// within a tight window on either side of the candidate, so a secret defined
// alongside a nearby HASURA_GRAPHQL_ADMIN_SECRET reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/version", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-hasura-admin-secret", secret)
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
