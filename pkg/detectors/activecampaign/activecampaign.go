// Package activecampaign detects ActiveCampaign API keys (60-80 char alnum).
// The matched Raw secret IS the ActiveCampaign API key, which the REST API
// accepts via the `Api-Token` request header. Verification uses
// GET <apiBase>/api/3/users/me (200 = valid, 401/403 = invalid). The
// account-specific host `https://<account>.api-us1.com` is not derivable from
// the chunk (the token carries no account), so Verify no-ops unless an apiBase
// override is supplied — the Jumio pattern. The nearKeyword vicinity gate and
// contextKeywords bound the false-positive rate on the unverified path.
package activecampaign

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

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{60,80})\b`)

// armRe is the assignment-style ActiveCampaign reference that must appear
// within the proximity window. No authoritative source pins the API key
// length/charset (the only documented example, `123abc-def-ghi`, is an
// illustrative placeholder), so the token regex is left untouched and the
// false-positive risk is carried entirely by this gate. A bare "activecampaign"
// / "api-us1" substring (doc links, the per-account `<account>.api-us1.com`
// host) is too weak against a generic 60-80 alphanumeric run; the
// `activecampaign…(api…)?(token|key|secret)` shape is what a real credential
// assignment or config key takes. The bare keyword stays in Keywords() as the
// engine prefilter.
var armRe = regexp.MustCompile(`(?i)(activecampaign|active_campaign|ac)[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 60-80 char runs (padded placeholders,
// repeated characters, structured non-secrets) that clear the alnum regex but
// lack key-grade randomness. Conservative 3.0 floor — no length/charset source
// exists, so a higher floor would silently destroy recall on real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ActiveCampaign }

func (Scanner) Keywords() []string { return []string{"activecampaign"} }

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
		// Entropy gate: structured/low-information 60-80 char runs clear the
		// alnum regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ActiveCampaign,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Verify only fires when an apiBase override supplies the per-account
		// host; otherwise it no-ops (the host is not derivable from the chunk).
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

// nearKeyword reports whether an assignment-style ActiveCampaign reference
// (armRe) appears within a tight window on either side of the candidate. The
// window spans both directions so a credential defined alongside a nearby
// AC_API_KEY reference still arms.
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

// Verify checks the API key against GET <apiBase>/api/3/users/me with the
// `Api-Token` header. It no-ops (false, nil) when no apiBase override is set,
// because the per-account host `<account>.api-us1.com` cannot be derived from
// the token alone. ClassifyVerifyHTTP keeps 429/5xx as transient errors rather
// than a false Verified verdict.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/3/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Api-Token", secret)
	req.Header.Set("User-Agent", "pleno-dlp/activecampaign")
	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
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
