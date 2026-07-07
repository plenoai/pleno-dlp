// Package zendesk detects Zendesk API tokens (40 alphanumerics near
// `zendesk` keyword) paired with the operator email Zendesk requires for
// Basic auth.
//
// Verify uses Zendesk's documented Basic-auth scheme
// base64(`<email>/token:<api_token>`) against
// GET https://<subdomain>.zendesk.com/api/v2/users/me.json. The tenant host
// is never guessed: it is derived from an in-chunk `<subdomain>.zendesk.com`
// match (or the apiBase test override). When neither the host nor the email
// is known, Verify no-ops (false, nil) rather than probing a guessed host —
// this avoids wrong-tenant audit-log entries while still letting tokens that
// ship with their tenant host be authoritatively verified. me.json is
// read-only/idempotent.
package zendesk

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase, when set, overrides the tenant host derived from the chunk. Tests
// point it at an httptest.Server. In production it is empty, so the host comes
// from the in-chunk `<subdomain>.zendesk.com` match.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}
)

// Zendesk API tokens are documented as 40 base62 chars — the token portion
// of the Basic-auth credential `<email>/token:<api_token>`.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)

// minEntropy rejects low-information 40-char base62 runs that satisfy the
// length+charset regex but are not random tokens (commit SHAs are hex/40 and
// cap near 3.6, padded placeholders and repeated-char runs sit well below).
// A real Zendesk token is high-variety; 3.5 culls the structured impostors
// without reaching into the random-token band.
const minEntropy = 3.5

// armRe is the Zendesk reference that must appear within the proximity window.
// A bare "zendesk" substring (a `<sub>.zendesk.com` host in a doc link or
// script-src URL) is too weak a gate against a generic 40-char base62 run.
// Two shapes arm:
//   - the assignment/config-key form `zendesk[_-]?(api[_-]?)?(token|key|secret)`
//     (e.g. ZENDESK_API_TOKEN=, zendesk_token=); and
//   - Zendesk's documented Basic-auth credential `<email>/token:<api_token>`,
//     whose literal `/token:` scheme separator (note the leading slash,
//     distinct from a bare `token:`) sits immediately before the token. This is
//     the canonical real-world shape from the Zendesk dev docs, so it must arm.
//
// The whole detector only runs after the "zendesk" Keywords() prefilter matches
// the chunk, so the `/token:` arm is already scoped to a Zendesk context.
var armRe = regexp.MustCompile(`(?i)(zendesk[_\-]?(api[_\-]?)?(token|key|secret)|/token:)`)

// RFC5322-ish email shape — kept conservative so we don't chase malformed
// addresses. We pair the operator email with the token via Basic auth.
var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b`)

var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.zendesk\.com)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zendesk }

func (Scanner) Keywords() []string { return []string{"zendesk"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	emails := emailRe.FindAllSubmatchIndex(data, -1)
	host := hostRe.FindString(string(data))
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// 40 alnum is far too generic — an armed zendesk credential reference
		// must co-occur within a tight window.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 40-char runs (commit SHAs,
		// padded placeholders, repeated-char runs) clear the length+charset
		// regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = strings.ToLower(host)
		}
		res := detectors.Result{
			DetectorType: detectors.Zendesk,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		var email string
		if e, ok := nearestRun(h[2], data, emails, 256); ok {
			email = e
			res.RawV2 = []byte(email)
			res.ExtraData["email"] = email
		}
		// Verify only when we have the complete credential: email + token +
		// a tenant host (derived from the chunk, or apiBase in tests). Without
		// any one of these the credential is incomplete and we never probe a
		// guessed host.
		if verify {
			v, err := verifyCredential(ctx, host, email, token)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, email, token, ok := splitTriple(secret)
	if !ok {
		return false, nil
	}
	return verifyCredential(ctx, host, email, token)
}

func splitTriple(s string) (host, email, token string, ok bool) {
	parts := strings.SplitN(s, "|", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func verifyCredential(ctx context.Context, host, email, token string) (bool, error) {
	base := apiBase
	if base == "" {
		if host == "" {
			return false, nil
		}
		base = "https://" + strings.ToLower(host)
	}
	if email == "" || token == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/users/me.json", nil)
	if err != nil {
		return false, err
	}
	// Zendesk Basic auth: username is "<email>/token", password is the token.
	cred := base64.StdEncoding.EncodeToString([]byte(email + "/token:" + token))
	req.Header.Set("Authorization", "Basic "+cred)

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, verifyAcceptCodes, verifyRejectCodes)
}

func nearestRun(idStart int, data []byte, runs [][]int, maxDistance int) (string, bool) {
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range runs {
		start, end := sm[2], sm[3]
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// nearKeyword reports whether a `zendesk[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby ZENDESK_API_TOKEN reference still arms.
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
