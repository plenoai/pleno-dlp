// Package mailgun detects Mailgun API keys (legacy "key-..." and the newer
// "<32 hex>-<8 hex>-<8 hex>" shape) and verifies them against /v3/domains
// using HTTP Basic auth (api:<key>).
package mailgun

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mailgun.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	legacyRe = regexp.MustCompile(`\b(key-[a-f0-9]{32})\b`)
	newRe    = regexp.MustCompile(`\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mailgun }

func (Scanner) Keywords() []string { return []string{"key-", "mailgun"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}

	for _, m := range legacyRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, makeResult(ctx, s, token, verify))
	}
	for _, m := range newRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, makeResult(ctx, s, token, verify))
	}
	return out, nil
}

func makeResult(ctx context.Context, s Scanner, token string, verify bool) detectors.Result {
	res := detectors.Result{
		DetectorType: detectors.Mailgun,
		Raw:          []byte(token),
		Redacted:     redact(token),
	}
	if verify {
		v, err := s.Verify(ctx, token)
		res.Verified = v
		res.VerificationErr = err
	}
	return res
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v3/domains", nil)
	if err != nil {
		return false, err
	}
	// Mailgun expects the literal "api" as the username and the key as
	// password; that's their documented Basic-auth contract.
	req.SetBasicAuth("api", secret)

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
