// Package mapbox detects Mapbox secret tokens (`sk.<base64url>`). Public
// tokens (`pk.…`) are publishable by design — they appear in browser
// bundles — so we deliberately do not emit them. Secret tokens grant the
// issuing account scope including dataset write and tile cache invalidation,
// so verified hits surface SeverityCritical.
//
// Verification calls /tokens/v2/<username> — but the username is
// embedded in the token's middle JWT segment. We decode it lazily and use
// it to construct the verify URL.
package mapbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mapbox.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sk.<base64url-segment>.<base64url-payload>.<base64url-sig>. The leading
// `sk.` distinguishes from `pk.` (public). Each segment is base64url.
var keyRe = regexp.MustCompile(`\b(sk\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mapbox }

func (Scanner) Keywords() []string { return []string{"sk."} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		// Filter for tokens that decode to a Mapbox-shaped JWT payload —
		// this rules out e.g. Stripe / sk.live.<...> false positives.
		username, ok := mapboxUsername(token)
		if !ok {
			continue
		}
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Mapbox,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    map[string]string{"username": username},
			// Secret tokens — destructive scope, surface SeverityCritical.
			Severity: detectors.SeverityCritical,
		}
		if verify {
			v, err := verifyToken(ctx, username, token)
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	username, ok := mapboxUsername(secret)
	if !ok {
		return false, nil
	}
	return verifyToken(ctx, username, secret)
}

func verifyToken(ctx context.Context, username, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	q := url.Values{}
	q.Set("access_token", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/tokens/v2/"+url.PathEscape(username)+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

// mapboxUsername decodes the middle JWT-style segment and returns the
// `u` claim (Mapbox username). If decoding fails, returns false.
func mapboxUsername(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", false
	}
	// parts[0] is "sk", parts[1] is the issuer/scope segment, parts[2] is
	// the payload, parts[3] is the signature.
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}
	var claims struct {
		U string `json:"u"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.U == "" {
		return "", false
	}
	return claims.U, true
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
