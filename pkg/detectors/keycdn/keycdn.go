// Package keycdn detects KeyCDN API keys. KeyCDN authenticates with HTTP
// Basic auth where the API key is the username and the password is empty
// (verified via /zones.json on api.keycdn.com).
//
// KeyCDN's official API documentation shows the secret CDN API key with a
// distinguishing `sk_prod_` prefix, e.g. the curl example authenticates as
// `sk_prod_<TOKEN>:` (https://www.keycdn.com/api). The prefix is the
// discriminator: it is anchored in the regex so the detector no longer
// depends on a bare alphanumeric run plus a wide keyword window.
package keycdn

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.keycdn.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe anchors on KeyCDN's documented `sk_prod_` secret-key prefix
// (https://www.keycdn.com/api). The single published example
// (`sk_prod_` + a 24-char mixed-case alphanumeric suffix) shows the shape,
// but KeyCDN does not document a fixed suffix length,
// so the suffix is matched as a generous {16,64} alphanumeric run rather
// than pinned to 24 (pinning a single-example length would silently
// destroy recall on any non-24-char key). The prefix is the false-positive
// gate; an entropy floor is unnecessary because `sk_prod_` does not occur
// in arbitrary text.
var tokenRe = regexp.MustCompile(`\b(sk_prod_[A-Za-z0-9]{16,64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.KeyCDN }

// Keywords keeps "keycdn" as the engine prefilter so the full regex only
// runs on chunks mentioning the provider; the `sk_prod_` prefix anchor in
// tokenRe does the actual matching.
func (Scanner) Keywords() []string { return []string{"keycdn"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h[1])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.KeyCDN,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/zones.json", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
