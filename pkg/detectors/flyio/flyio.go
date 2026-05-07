// Package flyio detects Fly.io macaroon tokens (fm1_/fm2_ prefixes) and
// verifies them by hitting the Machines API. Macaroons are URL-safe base64
// blobs of arbitrary length; we anchor on the prefix and require >=50
// chars after it so we don't hit on truncated examples.
//
// Verify quirk: a freshly-issued org token that has zero apps still returns
// 200 (with an empty list) on /v1/apps; a missing-app GET would 404. We
// treat both as verified — the token was authenticated. Only 401/403 are
// unverified, since they prove the token failed auth.
package flyio

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.fly.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// fm1_ or fm2_ + URL-safe base64 (alphanumeric + _ + -). We require >=50
// characters of body to skip non-token noise like "fm1_TODO".
var tokenRe = regexp.MustCompile(`\b(fm[12]_[A-Za-z0-9_-]{50,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.FlyIO }

func (Scanner) Keywords() []string { return []string{"fm1_", "fm2_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
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
		res := detectors.Result{
			DetectorType: detectors.FlyIO,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/apps", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNotFound:
		// 200 = listed; 404 = endpoint reachable but no apps. Both prove the
		// token authenticated.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	// Keep "fm?_" + 4 chars after = 8 chars total.
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
