// Package azurecr detects Azure Container Registry refresh / access tokens.
// ACR uses long JWT-style tokens (`<base64url>.<base64url>.<base64url>`)
// fetched via /oauth2/token from a per-registry host (`<name>.azurecr.io`).
//
// Verification strategy (two flows):
//
//  1. Access token: GET https://<registry>/v2/ with Authorization: Bearer <token>.
//     HTTP 200 = verified; 401 = not verified (token expired or insufficient scope).
//
//  2. Refresh token: POST https://<registry>/oauth2/token with
//     grant_type=refresh_token&service=<registry>&scope=repository:*:pull&refresh_token=<token>.
//     HTTP 200 with an access_token in the response body = verified.
//
// The registry host is extracted from the JWT payload (the same *.azurecr.io
// host used by the existing payloadIsACR gate). The token class (access vs
// refresh) is distinguished by checking for a "grant_type":"refresh_token"
// claim in the payload — present in refresh tokens, absent in access tokens.
// When the class is ambiguous, the detector tries the access-token probe
// first and falls back to the refresh-token exchange.
//
// Hardening: the JWT payload (middle base64url segment) is decoded and must
// self-identify as ACR — a claim (`aud`/`iss`/`service`/`grant_type`/`jti`
// region) must reference an `*.azurecr.io` host. JWTs whose decoded payload
// instead points at Azure AD endpoints (login.microsoftonline.com,
// sts.windows.net, graph.microsoft.com) are deferred to the AzureAD/AzureApp
// detectors. This turns "any JWT near a keyword" into "a JWT that
// self-identifies as ACR".
package azurecr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,400}\.[A-Za-z0-9_\-]{10,800}\.[A-Za-z0-9_\-]{10,400})\b`)

var contextKeywords = []string{"azurecr", ".azurecr.io", "acr_token", "acr_refresh", "acr_access", "acr_password"}

// azurecrHostRe matches a `<name>.azurecr.io` host inside the decoded JWT
// payload. Anchored on the literal ACR domain so an unrelated string can't
// satisfy it.
var azurecrHostRe = regexp.MustCompile(`[a-z0-9][a-z0-9\-]{0,49}\.azurecr\.io`)

// azureADHosts are negative lookalikes: a JWT whose decoded payload points at
// these endpoints is an Azure AD / Graph token, not an ACR token, and is
// handled by the AzureAD/AzureApp detectors.
var azureADHosts = []string{"login.microsoftonline.com", "sts.windows.net", "graph.microsoft.com", "login.windows.net"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureContainerRegistry }

func (Scanner) Keywords() []string { return []string{"azurecr", "acr_"} }

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
		// Required context-keyword vicinity within a tight radius. A far-away
		// unrelated JWT in the same chunk must not be swept in.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// The decoded payload must self-identify as ACR (and must not be an
		// Azure AD lookalike).
		if !payloadIsACR(token) {
			continue
		}
		// Entropy gate: real ACR tokens carry signed, high-entropy payload and
		// signature segments. Drop low-entropy placeholder/template JWTs.
		if !detectors.HasMinEntropy(payloadAndSignature(token), 3.5) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host, ok := extractACRHost(token); ok {
			extra["registry"] = host
		}
		res := detectors.Result{
			DetectorType: detectors.AzureContainerRegistry,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			verified, err := s.Verify(ctx, token)
			res.Verified = verified
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// extractACRHost decodes the JWT payload and extracts the *.azurecr.io
// hostname. Returns the host and true when found, or ("", false) when the
// payload cannot be decoded or contains no ACR host.
func extractACRHost(token string) (string, bool) {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return "", false
	}
	payload, ok := decodeSegment(segs[1])
	if !ok {
		return "", false
	}
	m := azurecrHostRe.FindString(strings.ToLower(payload))
	if m == "" {
		return "", false
	}
	return m, true
}

// isRefreshToken inspects the decoded JWT payload for a
// "grant_type":"refresh_token" claim, which identifies ACR refresh tokens.
// Access tokens lack this claim and carry permissions/scope claims instead.
func isRefreshToken(token string) bool {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return false
	}
	payload, ok := decodeSegment(segs[1])
	if !ok {
		return false
	}
	return strings.Contains(payload, `"grant_type"`) &&
		strings.Contains(payload, `"refresh_token"`)
}

// Verify confirms the ACR token is live by probing the registry extracted from
// the JWT payload. Access tokens are tested via GET /v2/; refresh tokens are
// exchanged via POST /oauth2/token (grant_type=refresh_token). When the token
// class is ambiguous, the access-token probe runs first with a refresh-token
// fallback.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, ok := extractACRHost(secret)
	if !ok {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if isRefreshToken(secret) {
		return verifyRefreshToken(ctx, host, secret)
	}
	// Try access-token probe first.
	verified, err := verifyAccessToken(ctx, host, secret)
	if verified || err != nil {
		return verified, err
	}
	// Fallback: the token might be a refresh token without the expected
	// grant_type claim. Try the refresh exchange.
	return verifyRefreshToken(ctx, host, secret)
}

// verifyAccessToken probes GET https://<registry>/v2/ with a Bearer token.
// HTTP 200 means the token is live and has at least catalog-level scope.
func verifyAccessToken(ctx context.Context, registry, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+registry+"/v2/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}

// verifyRefreshToken exchanges the refresh token for a short-lived access
// token via POST https://<registry>/oauth2/token. A 200 response containing
// an access_token proves the refresh token is live.
func verifyRefreshToken(ctx context.Context, registry, token string) (bool, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {registry},
		"scope":         {"repository:*:pull"},
		"refresh_token": {token},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+registry+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	// Parse just enough of the response to confirm an access_token was issued.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, nil
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &tokenResp) != nil {
		return false, nil
	}
	return tokenResp.AccessToken != "", nil
}

// payloadIsACR decodes the JWT's middle (payload) segment and reports whether
// it references an `*.azurecr.io` host. Returns false if the payload instead
// points at an Azure AD endpoint (deferred to AzureAD/AzureApp) or cannot be
// decoded. This is what makes a JWT "self-identify" as ACR rather than merely
// sitting near a keyword.
func payloadIsACR(token string) bool {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return false
	}
	payload, ok := decodeSegment(segs[1])
	if !ok {
		return false
	}
	lower := strings.ToLower(payload)
	// Azure AD / Graph lookalikes win: defer to the AzureAD/AzureApp detectors.
	for _, host := range azureADHosts {
		if strings.Contains(lower, host) {
			return false
		}
	}
	return azurecrHostRe.MatchString(lower)
}

// decodeSegment base64url-decodes a JWT segment, tolerating the missing
// padding that JWTs conventionally omit.
func decodeSegment(seg string) (string, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return string(b), true
	}
	// Fall back to padded decoding for non-conformant emitters.
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return string(b), true
	}
	return "", false
}

// payloadAndSignature returns the concatenated payload+signature segments,
// the high-entropy region of a genuine signed token.
func payloadAndSignature(token string) string {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return token
	}
	return segs[1] + segs[2]
}

func nearKeyword(lower string, start, end int) bool {
	// Tightened from 256 to 64 bytes: an ACR token is emitted right next to
	// its host/keyword (docker login lines, acr_* env assignments), so a far
	// keyword is coincidental, not corroborating.
	const radius = 64
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

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
