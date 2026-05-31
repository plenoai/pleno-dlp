// Package azurecr detects Azure Container Registry refresh / access tokens.
// ACR uses long JWT-style tokens (`<base64url>.<base64url>.<base64url>`)
// fetched via /oauth2/token from a per-registry host (`<name>.azurecr.io`).
//
// Unverified by design. The doc-row once claimed a `GET /v2/` registry probe
// using a host "parsed from the refresh token claim", but that is wrong:
// ACR refresh tokens (the dominant shape — what `docker login -p` and
// `acr_refresh` store) are NOT accepted by the Docker Registry v2 `/v2/`
// endpoint as a bearer. The real flow is two-leg —
// refresh_token -> POST /oauth2/token (grant_type=refresh_token, with the
// correct service=<host> and scope) -> access_token -> GET /v2/ with
// Authorization: Bearer <access_token>. A single-shot probe with the matched
// token would 401 every refresh token (mass false-negative), and the host is
// not reliably recoverable from the token alone without user config. So we do
// NOT implement Verify; instead we harden semantically.
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
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

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

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		out = append(out, detectors.Result{
			DetectorType: detectors.AzureContainerRegistry,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

func init() {
	detectors.Register(Scanner{})
}
