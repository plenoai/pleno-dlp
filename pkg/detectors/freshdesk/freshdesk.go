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

// Freshdesk API keys are documented as 20-char base62. We accept 20..40 to
// allow for any future key-length bumps without dropping coverage.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,40})\b`)

// Optional subdomain capture for ExtraData and verify host derivation.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.freshdesk\.com)\b`)

var contextKeywords = []string{"freshdesk", "freshworks"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Freshdesk }

func (Scanner) Keywords() []string { return []string{"freshdesk", "freshworks"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	host := hostRe.FindString(string(data))
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// 20+ alnum is far too generic without a Freshdesk co-occurrence
		// keyword in the same 256-byte window.
		if !nearKeyword(lower, h[2], h[3]) {
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
