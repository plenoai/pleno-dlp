// Package jwt detects JSON Web Tokens (header.payload.signature, base64url
// encoded) and surfaces the iss/sub claims in ExtraData. Verification is not
// possible without the signing secret/public key, so Verified is always false.
package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Header always begins with "eyJ" because every JWT header JSON starts with
// `{"` which base64url-encodes to "eyJ". Payload likewise.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JWT }

func (Scanner) Keywords() []string { return []string{"eyJ"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
		extra := decodeClaims(token)
		// Verify is intentionally not implemented — without the signing
		// secret/public key we can't check authenticity. Surface the JWT and
		// any iss/sub claims so reviewers can triage.
		res := detectors.Result{
			DetectorType: detectors.JWT,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		out = append(out, res)
	}
	return out, nil
}

// decodeClaims best-effort base64url-decodes header + payload and pulls the
// alg/iss/sub fields. Failures degrade to an empty map; we never error on a
// malformed JWT — the regex match alone is the finding.
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
			Aud string `json:"aud"`
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
