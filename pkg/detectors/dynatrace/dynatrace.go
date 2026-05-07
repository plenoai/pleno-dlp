// Package dynatrace detects Dynatrace API tokens — the documented shape is
// `dt0c01.<24-base32-id>.<64-base32-secret>`. The verify endpoint lives on
// the per-tenant host (`<env>.live.dynatrace.com` for SaaS or a managed
// hostname for self-hosted), which isn't carried in the chunk — verify
// requires apiBase override and is unverified-by-default; keyword + shape
// gating bound the false-positive rate.
package dynatrace

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase overrides the verify endpoint host. Default empty disables verify.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// dt0c01.<id>.<secret> — id is 24 base32 chars, secret is 64 base32 chars.
var tokenRe = regexp.MustCompile(`\b(dt0[a-z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Dynatrace }

func (Scanner) Keywords() []string { return []string{"dt0c01.", "dt0s16.", "dt0s08."} }

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
			DetectorType: detectors.Dynatrace,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/config/clusterversion", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Api-Token "+secret)
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
