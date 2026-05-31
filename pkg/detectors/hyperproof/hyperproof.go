// Package hyperproof detects Hyperproof (hyperproof.io) compliance
// API credentials (32-64 alnum) near the hyperproof keyword. Verified via
// /v1/users/me on api.hyperproof.app with an Authorization Bearer header
// carrying a <TOKEN> obtained from the OAuth client-credentials flow.
//
// Hyperproof's published docs do not pin the literal length/charset of the
// client_id/client_secret pair (the token endpoint is documented, the
// credential shape is not), so this detector keeps the conservative
// 32-64 alnum window and leans on a tight keyword arm + a low entropy floor
// rather than a fabricated length. The bare "hyperproof" Contains() gate over
// radius 256 was too weak against generic alnum runs — it is replaced by an
// assignment-style arm regex within radius 64, with "hyperproof" retained as
// the engine prefilter keyword.
package hyperproof

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.hyperproof.app"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Hyperproof reference that must appear within
// the proximity window. A bare "hyperproof" substring (doc links, the
// api.hyperproof.app host, prose) is too weak a gate against a generic 32-64
// alnum run; this is the shape a real credential assignment or config key
// takes (hyperproof_api_token, HYPERPROOF_CLIENT_SECRET, etc.).
var armRe = regexp.MustCompile(`(?i)hyperproof[_\-]?(api[_\-]?)?(client[_\-]?)?(token|key|secret|id)`)

// minEntropy rejects low-information 32-64 char runs that clear the alnum
// regex but are not credential-grade randomness (padded placeholders, repeated
// characters, dictionary-ish slugs). Conservative 3.0: the credential charset
// is undocumented and could be hex-leaning, where a 3.5 floor would over-cull.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Hyperproof }

func (Scanner) Keywords() []string { return []string{"hyperproof"} }

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
		// Entropy gate: structured/low-information 32-64 char runs that clear
		// the alnum regex but lack credential-grade randomness are rejected.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Hyperproof,
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

// nearKeyword reports whether a hyperproof credential-assignment reference
// (armRe) appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby HYPERPROOF_API_TOKEN reference arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users/me", nil)
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
