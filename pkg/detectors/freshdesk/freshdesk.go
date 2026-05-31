// Package freshdesk detects Freshdesk API keys (alphanumeric, ~20 chars,
// near `freshdesk` keyword).
//
// Verification is tenant-scoped: the Freshdesk REST API lives at
// `<subdomain>.freshdesk.com` and authenticates the API key via HTTP Basic
// auth (the key as username, any string — conventionally "X" — as password).
// We therefore only verify against a host that is actually present in the
// scanned chunk (captured by hostRe) or against an explicit apiBase override
// (used by tests). When neither host source is available we return
// Verified=false with no error rather than probing a guessed subdomain —
// guessing would risk wrong-account audit-log entries. This matches the
// tenant-scoped pattern already used for Grafana, BitbucketServer, Databricks
// and Confluence.
package freshdesk

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase, when non-empty, overrides the tenant host derived from the chunk.
// Production leaves it empty so the host comes from hostRe; tests point it at
// an httptest.Server.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

// Freshdesk API keys are documented as 20-char base62. The previous 20..40
// upper bound was load-bearing in the WRONG direction: a 40-char git SHA-1
// (lowercase hex) is exactly 40 chars and matches `[A-Za-z0-9]{20,40}`, so the
// old regex flagged every commit hash that happened to sit within 256 bytes of
// the word "freshdesk" (e.g. a CHANGELOG line "freshdesk connector @ <sha>").
// Entropy does NOT save us here: a 40-hex SHA scores ~3.74-3.80 bits/char,
// comfortably above the 3.5 base62 floor. The only reliable cut is the length
// bound — so we DROP the 40 ceiling. We cap at 32 (still well clear of the
// documented 20 and of any plausible future key bump) which structurally
// excludes the 40-char SHA: with `\b` anchors a 40-hex run cannot match a
// 32-char sub-slice (no word boundary mid-run).
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,32})\b`)

// Optional subdomain capture for ExtraData and verify host derivation.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.freshdesk\.com)\b`)

// assignAnchorRe matches an assignment-style Freshdesk/Freshworks reference
// (e.g. `freshdesk_api_key=`, `FRESHDESK_TOKEN:`, `freshworks-key =`). A bare
// "freshdesk" substring anywhere in a 256-byte window is too weak to arm a
// generic 20..32 alnum token; we require either this anchor OR a freshdesk.com
// host actually present in the chunk.
var assignAnchorRe = regexp.MustCompile(`(?i)fresh(?:desk|works)[a-z0-9_-]*\s*[:=]`)

// minEntropy is a SECONDARY base62 floor (alphabet ~62 → ceiling ≈ 6.0). It
// only rejects degenerate low-information runs; see the note in FromData on why
// it intentionally does NOT — and cannot — exclude git SHAs.
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
		// SECONDARY filter only. Drops degenerate runs ("aaaaaaaaaaaaaaaaaaaa",
		// "00000000000000000000") that clear the length floor. NOTE: this does
		// NOT cut git SHAs — a 40-hex SHA scores ~3.74-3.80 bits/char, above
		// 3.5 — that exclusion is done structurally by the 32-char cap in
		// tokenRe, not by entropy.
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
// expected as "<host>:<apikey>" (host being the tenant subdomain, e.g.
// "acme.freshdesk.com"); a bare key with no host yields Verified=false unless
// an apiBase override is configured.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, key, ok := strings.Cut(secret, ":")
	if !ok {
		// No host packed with the key — only verifiable via an apiBase
		// override (tests). Treat the whole string as the key.
		return verifyKey(ctx, "", secret)
	}
	return verifyKey(ctx, host, key)
}

// verifyKey performs the live check. Base URL precedence: apiBase override
// (tests) wins; otherwise the tenant host derived from the chunk. With neither
// we cannot pick a tenant, so we report unverified (no error) instead of
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
	// HTTP Basic auth: apikey as username, "X" as password.
	req.SetBasicAuth(key, "X")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, verifyAcceptCodes, verifyRejectCodes)
}

// nearAssignAnchor reports whether an assignment-style freshdesk/freshworks
// reference appears in the radius bytes immediately preceding the token. The
// crispchat detector uses radius 48; we use 64 to tolerate longer assignment
// keys plus surrounding quoting/whitespace (e.g. `FRESHDESK_API_KEY = "..."`).
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
