// Package paystack detects Paystack secret keys (`sk_(live|test)_`
// prefix + 40-50 alnum) near the `paystack` keyword. Verified via
// /transaction/totals on api.paystack.co with an Authorization Bearer
// header. The `sk_live_` variant surfaces SeverityCritical when matched
// (production payments credential).
package paystack

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.paystack.co"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Paystack secret keys: sk_(live|test)_ + 40-50 alnum chars.
var tokenRe = regexp.MustCompile(`\b(sk_(live|test)_[A-Za-z0-9]{40,50})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Paystack }

func (Scanner) Keywords() []string { return []string{"sk_live_", "sk_test_"} }

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
		// Disambiguate from Stripe / other `sk_(live|test)_` issuers by
		// requiring a `paystack` keyword nearby.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Paystack,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if strings.HasPrefix(token, "sk_live_") {
			res.Severity = detectors.SeverityCritical
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
	return strings.Contains(lower[from:to], "paystack")
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/transaction/totals", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
