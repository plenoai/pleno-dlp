// Package splunkhec detects Splunk HTTP Event Collector tokens (UUIDv4 near
// `splunk_hec` / `services/collector`). The bare UUID shape collides with
// arbitrary correlation ids, so co-occurrence with a Splunk-context keyword
// in a 256-byte window is mandatory.
//
// Verification: HEC endpoints live on per-customer hostnames
// (https://<host>:8088/services/collector/event) that aren't in the chunk, so
// the host is operator-supplied via the apiBase override. When apiBase is
// empty the Verify path no-ops (Verified=false, no error) and the finding
// surfaces under --unverified-results — the mandatory context-keyword gate
// bounds false positives on that path. When apiBase is set we POST to
// {apiBase}/services/collector/event with `Authorization: Splunk <token>`
// (NOT Bearer) and classify: 200 => valid, 401/403/400 => invalid,
// 429/5xx => transient.
package splunkhec

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the operator-supplied Splunk HEC host. Empty by default so the
// detector never invents a host; tests override it with an httptest server.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusBadRequest, // HEC "Invalid token" (code 4)
	}
)

var tokenRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

var contextKeywords = []string{
	"splunk_hec",
	"splunk-hec",
	"splunkhec",
	"services/collector",
	"hec_token",
	"splunk_token",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SplunkHEC }

func (Scanner) Keywords() []string { return []string{"splunk", "services/collector"} }

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
			DetectorType: detectors.SplunkHEC,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify checks a HEC token against the operator-supplied apiBase host. When
// apiBase is empty there is no host to talk to, so it no-ops as unverified
// (no error) per the apiBase-override convention shared with OneTrust /
// SemaphoreCI / JenkinsX.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret)
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Minimal valid HEC event payload — enough for the endpoint to accept it
	// when the token is valid, while a bad token deterministically returns
	// 401/403 (or 400 "Invalid token") before payload semantics matter.
	body := strings.NewReader(`{"event":"ping"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/services/collector/event", body)
	if err != nil {
		return false, err
	}
	// Splunk HEC uses the "Splunk" auth scheme, NOT Bearer.
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, verifyAcceptCodes, verifyRejectCodes)
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
