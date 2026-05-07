// Package gcpidtoken detects GCP ID tokens — JWT-shaped tokens issued by
// google-issued OIDC, with `iss=https://accounts.google.com` (or the
// service-account equivalent) and an `aud=` claim binding the token to a
// specific resource.
//
// Verify is intentionally not performed. ID tokens are audience-bound:
// validating one requires both Google's published JWKS (which we can fetch)
// and the expected audience (which the scanner doesn't know — the leak's
// security context depends on what `aud` was minted for). Probing the
// tokeninfo endpoint also leaves an audit-log trail. So gcpidtoken surfaces
// unverified-by-design and the engine renders it under --unverified-results.
//
// We do decode the payload to surface `iss` / `aud` / `email` / `sub` in
// ExtraData so reviewers can triage without re-decoding the token themselves.
package gcpidtoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// JWT shape (header.payload.signature, base64url). Same as pkg/detectors/jwt
// but we filter on the `iss` claim to claim only Google-issued tokens here.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCPIDToken }

// `eyJ` is shared with the generic jwt detector but we only emit when the
// decoded `iss` is one of Google's documented issuers, so duplicate findings
// across detectors don't fire.
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
		claims := decodeClaims(token)
		// Only claim google-issued tokens — defer to pkg/detectors/jwt for
		// everything else.
		iss := claims["iss"]
		if !isGoogleIssuer(iss) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.GCPIDToken,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    claims,
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func isGoogleIssuer(iss string) bool {
	switch iss {
	case "https://accounts.google.com",
		"accounts.google.com",
		"https://securetoken.google.com",
		"https://oauth2.googleapis.com":
		return true
	}
	// Service-account-issued tokens use the SA email as iss.
	return strings.HasSuffix(iss, ".iam.gserviceaccount.com") ||
		strings.HasSuffix(iss, "@system.gserviceaccount.com")
}

func decodeClaims(token string) map[string]string {
	out := map[string]string{}
	parts := splitJWT(token)
	if len(parts) != 3 {
		return out
	}
	if pl, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		var p struct {
			Iss   string `json:"iss"`
			Sub   string `json:"sub"`
			Aud   string `json:"aud"`
			Email string `json:"email"`
		}
		if json.Unmarshal(pl, &p) == nil {
			if p.Iss != "" {
				out["iss"] = p.Iss
			}
			if p.Sub != "" {
				out["sub"] = p.Sub
			}
			if p.Aud != "" {
				out["aud"] = p.Aud
			}
			if p.Email != "" {
				out["email"] = p.Email
			}
		}
	}
	return out
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
