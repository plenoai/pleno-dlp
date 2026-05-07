// Package snowflake detects Snowflake JWT keypair-auth tokens. These are
// RS256-signed JWTs whose `iss` claim embeds the Snowflake account and user
// in the form `<ACCOUNT>.<USER>.SHA256:<thumbprint>`.
//
// Verify is intentionally not performed. Snowflake JWTs are bound to a
// specific account host (`<account>.snowflakecomputing.com`) and validate
// against the public key registered for that user — both the account host
// and the matching public key must be available to confirm a leak. The
// scanner has neither in scope, and probing risks audit-log entries on
// the wrong account. We surface the leak unverified-by-design at
// SeverityHigh and emit the parsed `iss` / `sub` / `account` for triage.
package snowflake

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Snowflake }

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
		// Only claim Snowflake-shaped JWTs — `iss` must contain SHA256: and
		// follow the documented `<ACCOUNT>.<USER>.SHA256:` shape. This keeps
		// us from competing with the generic JWT detector on every JWT.
		iss := claims["iss"]
		if !strings.Contains(iss, ".SHA256:") {
			continue
		}
		account, user := splitIss(iss)
		if account != "" {
			claims["account"] = account
		}
		if user != "" {
			claims["user"] = user
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Snowflake,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    claims,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// splitIss parses `<ACCOUNT>.<USER>.SHA256:<thumb>` into (account, user).
// Returns empty strings when the shape does not match.
func splitIss(iss string) (string, string) {
	idx := strings.Index(iss, ".SHA256:")
	if idx < 0 {
		return "", ""
	}
	prefix := iss[:idx]
	dot := strings.LastIndex(prefix, ".")
	if dot < 0 {
		return prefix, ""
	}
	return prefix[:dot], prefix[dot+1:]
}

func decodeClaims(token string) map[string]string {
	out := map[string]string{}
	parts := splitJWT(token)
	if len(parts) != 3 {
		return out
	}
	if hdr, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		var h struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}
		if json.Unmarshal(hdr, &h) == nil {
			if h.Alg != "" {
				out["alg"] = h.Alg
			}
			if h.Typ != "" {
				out["typ"] = h.Typ
			}
		}
	}
	if pl, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		var p struct {
			Iss string `json:"iss"`
			Sub string `json:"sub"`
		}
		if json.Unmarshal(pl, &p) == nil {
			if p.Iss != "" {
				out["iss"] = p.Iss
			}
			if p.Sub != "" {
				out["sub"] = p.Sub
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
