// Package jwt detects JSON Web Tokens (header.payload.signature, base64url
// encoded) and surfaces decoded claims in ExtraData.
//
// Severity model (overrides DefaultSeverity for PrivateKeyPEM/JWT/Generic
// which would otherwise pin to Medium):
//
//   - alg=none                  → Critical, jwt_alg_none=true. The header
//     opts the token out of signing entirely; anyone can forge claims.
//     This is a vulnerability finding, not "an unverified credential."
//   - exp claim, in the past    → Low, jwt_status=expired. Still a leak
//     (refresh-token semantics, audit trail) but not a live credential.
//   - exp claim, in the future  → High, jwt_status=active.
//   - no exp claim              → Medium (default). Could be a long-lived
//     opaque token; could be a JSON-shaped payload that happens to look
//     like a JWT.
//
// Issuer tagging covers the well-known providers whose JWTs grant broad
// access:
//
//   - GitHub Actions OIDC (`token.actions.githubusercontent.com`) — repo
//     scope; can mint deploy creds via STS trust policies.
//   - Google (`accounts.google.com`, `*.googleapis.com`) — OAuth refresh
//     token equivalent.
//   - Auth0, Okta, Firebase, AWS Cognito — IdP tokens.
package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Header always begins with "eyJ" because every JWT header JSON starts with
// `{"` which base64url-encodes to "eyJ". Payload likewise.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

// nowFunc is the time source for expiration checks. Overridable from tests
// so we can pin "now" without leaking time mocks across the codebase.
var nowFunc = time.Now

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JWT }

func (Scanner) Keywords() []string { return []string{"eyJ"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := jwtRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		extra, severity := analyseToken(token)
		// Verify is intentionally not implemented — without the signing
		// secret/public key we can't check authenticity. Surface the JWT
		// and the decoded claims so reviewers can triage.
		res := detectors.Result{
			DetectorType: detectors.JWT,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
			Severity:     severity,
		}
		out = append(out, res)
	}
	return out, nil
}

// analyseToken decodes header+payload and returns the ExtraData map plus a
// severity override. Severity zero ("Unknown") means "let the engine apply
// DefaultSeverity"; non-zero pins this finding's class explicitly.
//
// The override exists because severity for a JWT depends on contents the
// engine cannot see: alg=none and expiry status are claim-derived signals
// that the generic Medium default ignores.
func analyseToken(token string) (map[string]string, detectors.Severity) {
	out := map[string]string{}
	parts := splitJWT(token)
	if len(parts) != 3 {
		return out, detectors.SeverityUnknown
	}

	severity := detectors.SeverityUnknown
	header := decodeJSON(parts[0])
	payload := decodeJSON(parts[1])

	// --- header --------------------------------------------------------
	if alg, ok := stringClaim(header, "alg"); ok {
		out["alg"] = alg
		// alg=none means "no signature" — the verification routine on the
		// receiving side accepts any payload. This is the canonical "JWT
		// security" footgun (CVE-2015-9235 et al). Severity Critical
		// regardless of expiry: even an expired alg=none token may be
		// usable as proof-of-knowledge somewhere downstream.
		if strings.EqualFold(alg, "none") {
			out["jwt_alg_none"] = "true"
			severity = detectors.SeverityCritical
		}
	}
	if typ, ok := stringClaim(header, "typ"); ok {
		out["typ"] = typ
	}
	if kid, ok := stringClaim(header, "kid"); ok {
		out["kid"] = kid
	}

	// --- payload -------------------------------------------------------
	if iss, ok := stringClaim(payload, "iss"); ok {
		out["iss"] = iss
		if tag := classifyIssuer(iss); tag != "" {
			out["issuer_class"] = tag
		}
	}
	if sub, ok := stringClaim(payload, "sub"); ok {
		out["sub"] = sub
	}
	if aud, ok := audClaim(payload); ok {
		out["aud"] = aud
	}
	if azp, ok := stringClaim(payload, "azp"); ok {
		out["azp"] = azp
	}
	if cid, ok := stringClaim(payload, "client_id"); ok {
		out["client_id"] = cid
	}
	if scope, ok := scopeClaim(payload); ok {
		out["scope"] = scope
	}
	if iat, ok := intClaim(payload, "iat"); ok {
		out["iat"] = strconv.FormatInt(iat, 10)
	}
	if nbf, ok := intClaim(payload, "nbf"); ok {
		out["nbf"] = strconv.FormatInt(nbf, 10)
	}

	// --- expiry-driven severity ---------------------------------------
	if exp, ok := intClaim(payload, "exp"); ok {
		out["exp"] = strconv.FormatInt(exp, 10)
		expTime := time.Unix(exp, 0)
		out["exp_iso"] = expTime.UTC().Format(time.RFC3339)
		// Only let expiry adjust severity if alg=none did NOT already
		// pin it to Critical — alg=none always wins.
		if severity == detectors.SeverityUnknown {
			if expTime.Before(nowFunc()) {
				out["jwt_status"] = "expired"
				severity = detectors.SeverityLow
			} else {
				out["jwt_status"] = "active"
				severity = detectors.SeverityHigh
			}
		}
	}

	return out, severity
}

// classifyIssuer returns a stable tag for well-known IdPs. Lower-cased
// substring match keeps the table small while covering tenant subdomains
// (`<tenant>.auth0.com`, `<tenant>.okta.com`).
func classifyIssuer(iss string) string {
	low := strings.ToLower(iss)
	switch {
	case strings.Contains(low, "token.actions.githubusercontent.com"):
		return "github-actions-oidc"
	case strings.Contains(low, "accounts.google.com"), strings.HasSuffix(low, ".googleapis.com"):
		return "google"
	case strings.Contains(low, ".auth0.com"):
		return "auth0"
	case strings.Contains(low, ".okta.com"), strings.Contains(low, ".oktapreview.com"):
		return "okta"
	case strings.Contains(low, "securetoken.google.com"), strings.Contains(low, "firebase"):
		return "firebase"
	case strings.Contains(low, "cognito-idp.") && strings.Contains(low, ".amazonaws.com"):
		return "aws-cognito"
	case strings.Contains(low, "login.microsoftonline.com"), strings.Contains(low, "sts.windows.net"):
		return "azure-ad"
	case strings.Contains(low, "id.atlassian.com"):
		return "atlassian"
	case strings.Contains(low, "slack.com"):
		return "slack"
	}
	return ""
}

// decodeJSON base64url-decodes a JWT segment and parses it as a JSON
// object. Returns nil on any failure — a malformed JWT segment must not
// crash the scan.
func decodeJSON(seg string) map[string]any {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Tolerate padded variants — some encoders pad even though
		// JWT spec forbids it.
		raw, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// stringClaim returns m[key] as a string when present and string-typed.
// Numeric or boolean values surface only via intClaim / explicit handlers.
func stringClaim(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// intClaim returns m[key] as int64. JSON numbers decode as float64 by
// default; we accept both float64 and json.Number-style strings.
func intClaim(m map[string]any, key string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// audClaim renders the `aud` claim. RFC 7519 says it is either a string
// or an array of strings; we join arrays with a comma so the ExtraData
// map stays string-valued.
func audClaim(m map[string]any) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m["aud"]
	if !ok {
		return "", false
	}
	switch x := v.(type) {
	case string:
		if x == "" {
			return "", false
		}
		return x, true
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, ","), true
	}
	return "", false
}

// scopeClaim renders the `scope` claim. OAuth2 spec uses a space-delimited
// string; some IdPs use a `scopes` array. Normalise to a comma-joined
// string so downstream tooling can split uniformly.
func scopeClaim(m map[string]any) (string, bool) {
	if m == nil {
		return "", false
	}
	if s, ok := stringClaim(m, "scope"); ok {
		// Re-join with comma so downstream parsing stays consistent
		// with the array variant below.
		return strings.Join(strings.Fields(s), ","), true
	}
	if v, ok := m["scopes"]; ok {
		if arr, ok := v.([]any); ok {
			parts := make([]string, 0, len(arr))
			for _, e := range arr {
				if s, ok := e.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ","), true
			}
		}
	}
	return "", false
}

func splitJWT(s string) []string {
	parts := []string{}
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[last:i])
			last = i + 1
		}
	}
	parts = append(parts, s[last:])
	return parts
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
