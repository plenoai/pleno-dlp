// Package braintree detects Braintree access tokens — a single
// `access_token$(production|sandbox)$<merchant_id>$<32 hex>` opaque string.
// The merchant id is embedded in the token so verify can pick the right
// gateway host (api.braintreegateway.com vs api.sandbox.braintreegateway.com)
// without out-of-band context. Raw carries the full token, RawV2 carries the
// merchant id segment so downstream tooling can route by environment.
package braintree

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBaseProd = "https://api.braintreegateway.com"
var apiBaseSandbox = "https://api.sandbox.braintreegateway.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// access_token$<env>$<merchant>$<32-hex>
var tokenRe = regexp.MustCompile(`\b(access_token\$(production|sandbox)\$([a-z0-9]{16,})\$([a-f0-9]{32}))\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Braintree }

func (Scanner) Keywords() []string { return []string{"access_token$"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m[1])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		merchant := string(m[3])
		res := detectors.Result{
			DetectorType: detectors.Braintree,
			Raw:          []byte(token),
			RawV2:        []byte(merchant),
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
	parts := strings.Split(secret, "$")
	if len(parts) != 4 {
		return false, nil
	}
	env, merchant := parts[1], parts[2]
	host := apiBaseProd
	if env == "sandbox" {
		host = apiBaseSandbox
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(host, "/")+"/merchants/"+merchant, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-ApiVersion", "6")
	req.Header.Set("Accept", "application/xml")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
