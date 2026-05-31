// Package wiz detects Wiz.io OAuth2 access tokens. Wiz mints short-lived
// JWT bearer tokens at auth.app.wiz.io/oauth/token; the durable credential is
// the client_id+client_secret pair, which this detector does NOT capture, so
// there is no RawV2 here.
//
// Verification is intentionally NOT implemented (class=b, unverified-by-design):
//   - the captured JWT is short-lived, so a live verify would falsely read as
//     expired/invalid even for once-genuine tokens;
//   - the Wiz GraphQL API host is tenant/data-center specific
//     (api.<tenant>.app.wiz.io/graphql) and is not reliably derivable from the
//     token or present in the chunk;
//   - the regex matches ANY JWT shape, so a fixed-host verify could mint a
//     false Verified=true against a non-Wiz JWT.
//
// Because the shape is a generic 3-segment JWT, precision rests entirely on the
// gating below: a Shannon-entropy floor per segment (drops aaaa.bbbb.cccc
// placeholders), a JWT-header decode that requires an "alg" claim (drops
// non-JWT lookalikes), a tight Wiz-distinctive keyword vicinity gate, and a
// negative exclusion for tokens whose decoded iss/aud clearly belong to another
// IdP (Google / Firebase / Auth0).
package wiz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_\-]{40,200}\.[A-Za-z0-9_\-]{40,200}\.[A-Za-z0-9_\-]{20,200})\b`)

// Wiz-distinctive context words. The bare `wiz` Keywords gate only narrows the
// engine's chunk set; this list is what actually attributes a JWT to Wiz.
var contextKeywords = []string{"wiz_io", "wiz.io", "wiz_token", "wiz_client_id", "wiz_client_secret", "auth.wiz.io", "app.wiz.io"}

// Issuers / audiences that unambiguously belong to another identity provider.
// If a candidate JWT decodes to one of these, it is not a Wiz token.
var foreignIssuerMarkers = []string{
	"accounts.google.com",
	"securetoken.google.com",
	".auth0.com",
	"auth0.com/",
}

// base64url alphabet tokens of length >=40 reach ~5.5+ bits/char when random;
// 3.5 is a conservative floor that still rejects repeated-char placeholders.
const minSegmentEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Wiz }

func (Scanner) Keywords() []string { return []string{"wiz"} }

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
		if !looksLikeJWT(token) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Wiz,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// looksLikeJWT applies the semantic gates that distinguish a real JWT bearer
// token from a dotted-shape lookalike or a foreign-IdP JWT:
//  1. each of the three segments must clear the entropy floor (kills
//     aaaa.bbbb.cccc and other low-entropy template placeholders);
//  2. the first segment must base64url-decode to a JSON object carrying an
//     "alg" claim (kills arbitrary dotted base64url that is not a JWT header);
//  3. the payload's iss/aud, when decodable, must not name a foreign IdP.
func looksLikeJWT(token string) bool {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return false
	}
	for _, seg := range segs {
		if !detectors.HasMinEntropy(seg, minSegmentEntropy) {
			return false
		}
	}

	header := decodeSegment(segs[0])
	if header == nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		return false
	}
	if hdr.Alg == "" {
		return false
	}

	// Negative-lookalike exclusion: if the payload decodes and names another
	// IdP, this is not a Wiz token. Undecodable payloads are not excluded —
	// absence of evidence is not evidence of a foreign issuer.
	if payload := decodeSegment(segs[1]); payload != nil {
		var claims struct {
			Iss string `json:"iss"`
			Aud string `json:"aud"`
		}
		if err := json.Unmarshal(payload, &claims); err == nil {
			haystack := strings.ToLower(claims.Iss + " " + claims.Aud)
			for _, marker := range foreignIssuerMarkers {
				if strings.Contains(haystack, marker) {
					return false
				}
			}
		}
	}
	return true
}

func decodeSegment(seg string) []byte {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b
	}
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return b
	}
	return nil
}

func nearKeyword(lower string, start, end int) bool {
	// 96 bytes (down from 256) keeps the Wiz keyword close enough to the token
	// to be a real annotation rather than an unrelated mention elsewhere in a
	// wiz-discussing file.
	const radius = 96
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
