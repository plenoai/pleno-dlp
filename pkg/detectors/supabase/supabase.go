// Package supabase detects Supabase service-role / anon keys (JWT with a
// Supabase-shaped `role` claim near a `supabase` keyword) and verifies them
// against the project's PostgREST endpoint.
//
// Verify is correct and confident for the common hosted case: a hosted
// Supabase JWT embeds `"ref":"<project-ref>"` in its payload, and
// `https://<ref>.supabase.co/rest/v1/` is the exact REST host that accepts
// this same JWT via the `apikey` / `Authorization: Bearer` header. Because
// the host is derived from the token itself we always probe the key's own
// tenant — there is no wrong-tenant false positive. We prefer the JWT `ref`
// claim and fall back to a `ref` captured from a `https://<ref>.supabase.co`
// URL in the same chunk. When neither is present (custom domains /
// self-hosted tokens without a ref claim) Verify no-ops and the finding is
// surfaced unverified.
package supabase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase, when set, overrides the per-project host derived from the token
// (tests point it at an httptest.Server). Empty in production: the host is
// computed as https://<ref>.supabase.co.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

// JWT shape — same prefix gate as the generic JWT detector. The
// supabase-specific filter is the `role` claim plus the keyword.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})\b`)

// Project URL ref capture: https://<ref>.supabase.co.
var projectRe = regexp.MustCompile(`\bhttps?://([a-z0-9-]{20})\.supabase\.co\b`)

var contextKeywords = []string{"supabase", "supabase_url", "supabase_anon", "supabase_service_role", "service_role"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Supabase }

func (Scanner) Keywords() []string { return []string{"supabase", "service_role"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := jwtRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	// Project ref is shared across all keys in the chunk.
	projectRef := ""
	if pm := projectRe.FindStringSubmatch(string(data)); len(pm) == 2 {
		projectRef = pm[1]
	}

	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		role, ref := parseClaims(token)
		// Only claim Supabase JWTs — payload must carry a Supabase-shaped
		// `role` claim. This keeps us out of the generic JWT detector's
		// keyspace.
		if role == "" {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{"role": role}
		if ref != "" {
			extra["jwt_project_ref"] = ref
		}
		if projectRef != "" {
			extra["project_ref"] = projectRef
		}
		// Service-role keys are admin-equivalent — surface Critical even
		// without verification. anon keys still leak project identity but
		// expose no row-level admin path; surface High via package default.
		sev := detectors.SeverityHigh
		if role == "service_role" {
			sev = detectors.SeverityCritical
		}
		res := detectors.Result{
			DetectorType: detectors.Supabase,
			Raw:          []byte(token),
			Redacted:     redact(token),
			Severity:     sev,
			ExtraData:    extra,
		}
		// Prefer the ref embedded in the JWT (always the key's own tenant);
		// fall back to a ref captured from a supabase.co URL in the chunk.
		host := projectHost(ref)
		if host == "" {
			host = projectHost(projectRef)
		}
		if verify && host != "" {
			v, err := verifyToken(ctx, host, token)
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

// Verify implements detectors.Verifier. The host is derived solely from the
// token's own `ref` claim, so we always probe the key's own project — never a
// foreign tenant. Tokens without a ref claim (custom/self-hosted) can't be
// verified here and no-op to (false, nil).
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	_, ref := parseClaims(secret)
	host := projectHost(ref)
	if host == "" {
		return false, nil
	}
	return verifyToken(ctx, host, secret)
}

// projectHost computes the PostgREST base for a hosted project ref, or honours
// the apiBase test override. Returns "" when no host can be derived.
func projectHost(ref string) string {
	if apiBase != "" {
		return apiBase
	}
	if ref == "" {
		return ""
	}
	return "https://" + ref + ".supabase.co"
}

// verifyToken probes <host>/rest/v1/ with the JWT in both the apikey header
// (PostgREST's primary auth) and Authorization: Bearer. 200 → valid;
// 401/403 → rejected; 429/5xx → transient (surfaced as VerificationErr).
func verifyToken(ctx context.Context, host, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/rest/v1/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("apikey", token)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, err, verifyAcceptCodes, verifyRejectCodes)
}

// parseClaims extracts (role, ref) from the JWT payload. ref is the
// `ref` claim that supabase embeds for hosted projects. Both default
// to "" on parse failure.
func parseClaims(token string) (string, string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", ""
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var p struct {
		Role string `json:"role"`
		Ref  string `json:"ref"`
	}
	if err := json.Unmarshal(pl, &p); err != nil {
		return "", ""
	}
	return p.Role, p.Ref
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
