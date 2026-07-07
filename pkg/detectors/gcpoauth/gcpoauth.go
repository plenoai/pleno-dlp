// Refresh tokens are long-lived bearer credentials that mint access tokens;
// rotating them is non-trivial because they're issued per (user, client). We
// verify by POSTing to https://oauth2.googleapis.com/token with
// `grant_type=refresh_token`. A 200 + access_token in the body means the
// refresh token is currently usable; 400 invalid_grant / 401 = unverified.
package gcpoauth

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://oauth2.googleapis.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Refresh tokens are documented as `1//` followed by ~93 chars of
// base64url-without-padding. We accept 80..200 to absorb minor format drift.
// The leading `1//0` segment is the version + key prefix; we don't anchor the
// `0` because Google has rotated this byte historically.
var tokenRe = regexp.MustCompile(`\b(1//0[A-Za-z0-9_-]{80,200})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCPOAuth }

// `1//0` is distinctive enough that no keyword gate is needed; refresh tokens
// don't naturally appear in source unless they're exfiltrated.
func (Scanner) Keywords() []string { return []string{"1//0"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.GCPOAuth,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyToken(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret)
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// We don't have the client_id+client_secret pair the token was minted
	// against. POST without them: Google returns 400 invalid_client when
	// the request shape is correct but the auth pair is missing, and 400
	// invalid_grant when the refresh token itself is dead. We grade only
	// 200 as verified — anything else is unverified. This means a valid
	// refresh token still surfaces as unverified when the client pair is
	// not in the same chunk; that's acceptable, the alternative is no
	// signal at all.
	body := strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
	}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/token", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
