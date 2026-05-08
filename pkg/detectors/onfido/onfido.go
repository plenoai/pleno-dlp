// Package onfido detects Onfido (onfido.com) KYC API tokens
// (`api_(live|sandbox)_(us|eu|ca)_` prefix + alnum) near the `onfido`
// keyword. Verified via /v3.6/applicants on api.onfido.com with
// Authorization Token header.
package onfido

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.onfido.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Onfido tokens: api_(live|sandbox)_(us|eu|ca)_ + 40 alnum.
var tokenRe = regexp.MustCompile(`\b(api_(?:live|sandbox)_(?:us|eu|ca)_[A-Za-z0-9_-]{32,80})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Onfido }

func (Scanner) Keywords() []string { return []string{"api_live_", "api_sandbox_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Onfido,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3.6/applicants", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token token="+secret)
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
