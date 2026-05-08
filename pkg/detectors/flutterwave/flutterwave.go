// Package flutterwave detects Flutterwave secret keys (`FLWSECK-` /
// `FLWSECK_TEST-` prefix + 32-64 alnum) near the `flutterwave` keyword.
// Verified via /v3/transactions on api.flutterwave.com with an
// Authorization Bearer header.
package flutterwave

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.flutterwave.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Flutterwave secret keys: `FLWSECK-` (live) or `FLWSECK_TEST-` (test)
// followed by 32-64 alnum / dash / X chars (the trailing -X is documented).
var tokenRe = regexp.MustCompile(`\b(FLWSECK(?:_TEST)?-[A-Za-z0-9]{20,64}(?:-X)?)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Flutterwave }

func (Scanner) Keywords() []string { return []string{"FLWSECK"} }

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
			DetectorType: detectors.Flutterwave,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if !strings.Contains(token, "_TEST") {
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3/transactions", nil)
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
