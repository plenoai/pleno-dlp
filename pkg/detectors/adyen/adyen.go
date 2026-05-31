// Package adyen detects Adyen API keys (long alnum prefixed by AQE/AQF) gated
// on the `adyen` keyword window, and verifies them live against the Adyen
// Checkout API.
//
// Adyen authenticates every Checkout API request solely via the X-API-Key
// header, so the matched Raw value is exactly the credential the endpoint
// accepts — there is no key+secret pairing. The TEST host is fixed and public
// (https://checkout-test.adyen.com) and the regex matches test keys (AQF
// prefix); the merchant account is a request-BODY field, not part of the auth,
// so its absence yields 400/403/422 (request reached past auth) rather than
// 401. We therefore POST /v71/paymentMethods with a minimal body and treat a
// non-401 response as "key valid". Live keys (AQE prefix) require a
// merchant-specific live URL prefix that is not token-derivable; operators may
// supply it via the apiBase override. Probing a live key against the fixed
// test host fails closed to 401 (Verified=false), never a false positive.
package adyen

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the Checkout API host used for verification. Defaults to the
// fixed public TEST host; tests (and operators with a live merchant prefix)
// override it.
var apiBase = "https://checkout-test.adyen.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// acceptCodes: any status that means the request authenticated past the
// X-API-Key gate. A valid key with a missing/empty merchantAccount yields
// 400/403/422, not 401. rejectCodes: 401 is unambiguously an auth rejection.
var (
	acceptCodes = []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity}
	rejectCodes = []int{http.StatusUnauthorized}
)

// Adyen keys typically start with AQE (live) or AQF (test) and are long
// base64url-ish strings (64+ chars). Tighten on the AQ prefix to avoid
// generic base64 noise.
var tokenRe = regexp.MustCompile(`\b(AQE[A-Za-z0-9+/=]{40,200}|AQF[A-Za-z0-9+/=]{40,200})\b`)

var contextKeywords = []string{"adyen", "adyen_api_key", "adyen_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Adyen }

func (Scanner) Keywords() []string { return []string{"adyen"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Adyen,
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

// Verify performs a live auth-only probe: POST <apiBase>/v71/paymentMethods
// with the X-API-Key header and a minimal JSON body. ClassifyVerifyHTTP maps
// non-401 (accept) to verified, 401 (reject) to not-verified, and 429/5xx to
// a transient error so the engine reports "verification failed" rather than a
// false negative.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	body := strings.NewReader(`{"merchantAccount":""}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v71/paymentMethods", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-Key", secret)
	req.Header.Set("Content-Type", "application/json")

	resp, transportErr := httpClient.Do(req)
	if transportErr == nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, transportErr, acceptCodes, rejectCodes)
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
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
