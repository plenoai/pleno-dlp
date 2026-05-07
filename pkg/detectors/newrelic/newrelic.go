// Package newrelic detects New Relic keys in three flavors:
//
//   - NRRA-... license keys (a.k.a. user API keys; 42-char URL-safe tail).
//     Verifiable against /v2/applications.json with X-Api-Key.
//   - NRAK-... ingest keys (27 upper-alnum). No public verify endpoint.
//   - NRII-... insert keys (32 mixed). No public verify endpoint.
//
// The kind is captured in ExtraData["kind"] so reviewers can route by class.
package newrelic

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.newrelic.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	licenseRe = regexp.MustCompile(`\b(NRRA-[a-zA-Z0-9-]{42})\b`)
	ingestRe  = regexp.MustCompile(`\b(NRAK-[A-Z0-9]{27})\b`)
	insertRe  = regexp.MustCompile(`\b(NRII-[A-Za-z0-9-]{32})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.NewRelic }

func (Scanner) Keywords() []string { return []string{"NRRA-", "NRAK-", "NRII-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}

	for _, m := range licenseRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.NewRelic,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    map[string]string{"kind": "license"},
		}
		// Only the NRRA flavor is verifiable; NRAK / NRII have no public
		// validate endpoint.
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}

	// NRAK / NRII are regex-only. We mark them ExtraData["kind"] so reviewers
	// can tell them apart and so the engine doesn't flatten them into a
	// generic NewRelic finding.
	for _, m := range ingestRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.NewRelic,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    map[string]string{"kind": "ingest"},
		})
	}
	for _, m := range insertRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.NewRelic,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    map[string]string{"kind": "insert"},
		})
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/applications.json", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Api-Key", secret)

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
	// Keep "NRxx-" + 4 chars after = 9 chars.
	if len(t) <= 9 {
		return t
	}
	return t[:9] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
