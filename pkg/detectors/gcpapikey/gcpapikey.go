// AIza-prefixed keys gate access to public Google APIs (Maps, Translate,
// YouTube Data, Firebase), not service-account level, but still a leak that
// can drive billing abuse on the owner's project. We verify by hitting the
// public API discovery endpoint with the key as a query parameter; a 200
// confirms the key is currently active and not revoked.
package gcpapikey

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://www.googleapis.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// AIza<35 chars> is the documented format. The character class is the
// base64url-without-padding alphabet.
var keyRe = regexp.MustCompile(`\b(AIza[A-Za-z0-9_-]{35})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCPAPIKey }

// `AIza` is the unmistakable prefix; no keyword gate needed.
func (Scanner) Keywords() []string { return []string{"AIza"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAll(data, -1)
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
			DetectorType: detectors.GCPAPIKey,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyKey(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyKey(ctx, secret)
}

func verifyKey(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := apiBase + "/discovery/v1/apis?" + url.Values{"key": {key}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		// 400 = API_KEY_INVALID, 403 = API_KEY_HTTP_REFERRER_BLOCKED or
		// API key disabled. Either way: not usable as a leaked credential.
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
