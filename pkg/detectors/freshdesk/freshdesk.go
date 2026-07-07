// Verification is tenant-scoped: the Freshdesk API lives at
// `<subdomain>.freshdesk.com` and authenticates via HTTP Basic auth (key as
// username, arbitrary password). We only verify against a host present in
// the chunk or an apiBase override; with neither we return Verified=false
// with no error rather than probing a guessed subdomain, which would risk
// wrong-account audit-log entries.
package freshdesk

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

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

// Freshdesk API keys are documented as 20-char base62. The previous 20..40
// upper bound matched 40-char git SHA-1 hashes, which clear the 3.5 entropy
// floor at ~3.74-3.80 bits/char, flagging every commit hash near the word
// "freshdesk". The only reliable cut is the length bound, so we cap at 32:
// well clear of the documented 20, and with `\b` anchors a 40-hex run cannot
// match a 32-char sub-slice.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,32})\b`)

var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.freshdesk\.com)\b`)

// A bare "freshdesk" substring anywhere in a 256-byte window is too weak to
// arm a generic 20..32 alnum token; we require either this anchor OR a
// freshdesk.com host actually present in the chunk.
var assignAnchorRe = regexp.MustCompile(`(?i)fresh(?:desk|works)[a-z0-9_-]*\s*[:=]`)

// minEntropy only rejects degenerate low-information runs; see the note on
// tokenRe for why it intentionally does NOT — and cannot — exclude git SHAs.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Freshdesk }

func (Scanner) Keywords() []string { return []string{"freshdesk", "freshworks"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	host := hostRe.FindString(string(data))
	// A freshdesk.com host anywhere in the chunk is itself a strong tenant
	// signal; otherwise we fall back to a per-token assignment anchor.
	hasHost := host != ""
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// PRIMARY gate. 20..32 alnum is far too generic to surface on a bare
		// keyword co-occurrence. Require EITHER a freshdesk.com host in the
		// chunk OR an assignment-style freshdesk/freshworks anchor in the
		// window immediately preceding the token.
		if !hasHost && !nearAssignAnchor(lower, h[2]) {
			continue
		}
		// SECONDARY filter: drops degenerate low-information runs that clear
		// the length floor; git-SHA exclusion is handled structurally by the
		// 32-char cap in tokenRe, not by entropy.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = strings.ToLower(host)
		}
		res := detectors.Result{
			DetectorType: detectors.Freshdesk,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			v, err := verifyKey(ctx, host, token)
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

// Verify checks a Freshdesk API key against the tenant host. The secret is
// expected as "<host>:<apikey>"; a bare key with no host yields
// Verified=false unless an apiBase override is configured.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, key, ok := strings.Cut(secret, ":")
	if !ok {
		return verifyKey(ctx, "", secret)
	}
	return verifyKey(ctx, host, key)
}

// verifyKey performs the live check. Base URL precedence: apiBase override
// wins; otherwise the tenant host derived from the chunk. With neither we
// cannot pick a tenant, so we report unverified (no error) instead of
// guessing a subdomain.
func verifyKey(ctx context.Context, host, key string) (bool, error) {
	base := apiBase
	if base == "" {
		if host == "" {
			return false, nil
		}
		base = "https://" + strings.ToLower(host)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/agents/me", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, "X")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, verifyAcceptCodes, verifyRejectCodes)
}

// The crispchat detector uses radius 48; we use 64 to tolerate longer
// assignment keys plus surrounding quoting/whitespace.
func nearAssignAnchor(lower string, start int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	window := lower[from:start]
	return assignAnchorRe.MatchString(window)
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
