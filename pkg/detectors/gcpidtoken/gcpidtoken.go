// Package gcpidtoken detects GCP ID tokens — JWT-shaped tokens issued by
// google-issued OIDC, with `iss=https://accounts.google.com` (or the
// service-account equivalent) and an `aud=` claim binding the token to a
// specific resource.
//
// Verification uses the Google tokeninfo endpoint
// (https://oauth2.googleapis.com/tokeninfo?id_token=<token>). A 200 with
// valid JSON means the token is live and Google-accepted; 4xx means expired
// or invalid. On success the response's "email_verified" and "azp" fields
// are added to ExtraData for blast-radius context.
//
// Note: the tokeninfo endpoint is rate-limited by Google. The scanner
// should not be run in a tight loop against thousands of tokens.
//
// We also decode the payload to surface `iss` / `aud` / `email` / `sub` in
// ExtraData so reviewers can triage without re-decoding the token themselves.
package gcpidtoken

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

// JWT shape (header.payload.signature, base64url). Same as pkg/detectors/jwt
// but we filter on the `iss` claim to claim only Google-issued tokens here.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

var httpClient = &http.Client{Timeout: 10 * time.Second}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCPIDToken }

// `eyJ` is shared with the generic jwt detector but we only emit when the
// decoded `iss` is one of Google's documented issuers, so duplicate findings
// across detectors don't fire.
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
		if verify {
			v, extra, err := s.verifyWithMetadata(ctx, token)
			res.Verified = v
			res.VerificationErr = err
			for k, val := range extra {
				claims[k] = val
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify satisfies detectors.Verifier. It probes Google's tokeninfo
// endpoint to check whether the token is still live.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := s.verifyWithMetadata(ctx, secret)
	return v, err
}

// verifyWithMetadata calls the tokeninfo endpoint and returns both the
// verified flag and any enrichment fields (email_verified, azp) for
// ExtraData.
func (Scanner) verifyWithMetadata(ctx context.Context, token string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := "https://oauth2.googleapis.com/tokeninfo?id_token=" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 4xx = expired or invalid token — not an error, just unverified.
		return false, nil, nil
	}

	// Parse the tokeninfo response to extract blast-radius context.
	var info struct {
		EmailVerified string `json:"email_verified"`
		Azp           string `json:"azp"`
	}
	meta := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err == nil {
		if info.EmailVerified != "" {
			meta["email_verified"] = info.EmailVerified
		}
		if info.Azp != "" {
			meta["azp"] = info.Azp
		}
	}
	return true, meta, nil
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
	// Split JWT on '.' to extract the payload (middle segment).
	parts := []string{}
	last := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[last:i])
			last = i + 1
		}
	}
	parts = append(parts, token[last:])
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

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
