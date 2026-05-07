// Package stripe detects Stripe live/test secret keys (sk_live_, sk_test_,
// rk_live_) and verifies them via the /v1/charges list endpoint.
package stripe

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.stripe.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sk_live_, sk_test_, rk_live_ all share the same suffix shape: 20–247 base62
// chars. trufflehog uses the same canonical pattern.
var keyRe = regexp.MustCompile(`\b((?:sk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,247})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Stripe }

func (Scanner) Keywords() []string { return []string{"sk_live_", "sk_test_", "rk_live_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.Stripe,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/charges", nil)
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
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

// redact preserves the recognizable provider prefix plus four chars so
// operators can correlate findings without seeing the live secret.
func redact(t string) string {
	for _, p := range []string{"sk_live_", "sk_test_", "rk_live_"} {
		if len(t) > len(p)+4 && t[:len(p)] == p {
			return t[:len(p)+4] + "..."
		}
	}
	if len(t) > 8 {
		return t[:8] + "..."
	}
	return t + "..."
}

func init() {
	detectors.Register(Scanner{})
}
