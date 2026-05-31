// Package opslevel detects OpsLevel (opslevel.com) API tokens (mixed-case
// alnum) armed by an OpsLevel token/key/secret reference. Verified via the
// GraphQL endpoint
// /graphql on api.opslevel.com with Authorization Bearer header (probes
// `query{account{id}}`, surfacing 200 on a valid token).
package opslevel

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.opslevel.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// OpsLevel API tokens are mixed-case alphanumeric strings used as a Bearer
// credential. OpsLevel's docs do NOT publish a length or charset spec; the
// only authoritative sample (docs.opslevel.com/docs/package-versions,
// "Bearer <TOKEN>") is 36 chars of [A-Za-z0-9]. A single example is not an
// authoritative length pin, so we do not pin a tight length: the range keeps
// the documented 36-char shape in scope and bounds the upper end to avoid
// matching arbitrarily long alnum runs. Recall is protected by the arm regex
// + entropy floor below rather than by a fragile length pin.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{36,64})\b`)

// armRe is the assignment-style OpsLevel reference that must appear within a
// tight proximity window. A bare "opslevel" substring (doc URLs, dependency
// names, comments) is too weak to arm a high-entropy alnum match; an
// `opslevel[_-]?(api[_-]?)?(token|key|secret)` shape is what a real token
// assignment or config key looks like.
var armRe = regexp.MustCompile(`(?i)ops[_\-]?level[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information alnum runs that clear the length regex
// but are not random credentials (padded identifiers, repeated patterns).
// OpsLevel charset is high-variety mixed-case alnum; the documented sample
// scores ~4.56. A conservative 3.0 floor culls structured junk without
// risking recall on a real token whose length/charset are undocumented.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OpsLevel }

func (Scanner) Keywords() []string { return []string{"opslevel"} }

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
		// Entropy gate: a 36-64 char alnum run that is armed but
		// low-information (padded names, repeated patterns) is not a token.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.OpsLevel,
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

// nearKeyword reports whether an `opslevel[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby OPSLEVEL_API_TOKEN reference still arms.
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
	body := strings.NewReader(`{"query":"{ account { id } }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/graphql", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
