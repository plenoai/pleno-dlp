// Package klaviyo detects Klaviyo private (`pk_…`) and public (`sk_…`) API
// keys and verifies them against /api/v2/profiles using the documented
// `Authorization: Klaviyo-API-Key …` header.
//
// Klaviyo's `pk_` is the private/server key (full account read+write); `sk_`
// is the legacy site key. We treat `pk_` as the higher-severity carrier but
// still scan both shapes.
package klaviyo

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://a.klaviyo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Klaviyo private keys: `pk_<32-hex-or-base62>`. Site keys: `sk_<32-…>` or
// `pk_…` shape, also documented as 6+ char base62 in some docs. We accept
// 32..64 chars body; the prefix gate is enough to avoid noise.
var tokenRe = regexp.MustCompile(`\b((?:pk|sk)_[A-Za-z0-9]{32,64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Klaviyo }

// `pk_` collides with Stripe's publishable key prefix. We disambiguate by
// regex body length (Stripe uses 24+ chars but the keyword and the verify
// endpoint are different). Adding `klaviyo` as a keyword would make the gate
// too strict for env-file dumps that just have `KLAVIYO_PRIVATE_KEY=pk_…`.
func (Scanner) Keywords() []string { return []string{"pk_", "sk_", "klaviyo"} }

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
			DetectorType: detectors.Klaviyo,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/profiles", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Klaviyo-API-Key "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		// 400 with `{"detail":"Invalid api key"}` is the wrong-token shape.
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
