// Package teamcity detects JetBrains TeamCity server access tokens (40+ char
// base62 near `teamcity`). TeamCity is typically self-hosted and TeamCity
// Cloud uses per-customer subdomains, so the verification host is neither in
// the chunk nor derivable from the token. Verify therefore follows the
// apiBase-override pattern: when apiBase is unset (the default) it no-ops and
// returns (false, nil); operators who supply --teamcity-api-base get a live
// bearer-credential check against GET {apiBase}/app/rest/server. Because a
// wrong/absent host yields a transport error (surfaced as VerificationErr,
// never Verified=true), there is no false-positive risk.
package teamcity

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is empty by default: TeamCity is self-hosted, so there is no canonical
// host. Operators (and tests, via httptest.Server) override it to enable live
// verification. Tests assign this package-level var to point at a local server.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// acceptCodes/rejectCodes per the verify plan: 200 = valid bearer token,
// 401/403/404 = explicit rejection. 429 and 5xx are transient (handled by
// ClassifyVerifyHTTP) and surface as VerificationErr.
var (
	acceptCodes = []int{http.StatusOK}
	rejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}
)

var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_.-]{20,}|[A-Za-z0-9]{40,80})\b`)

var contextKeywords = []string{
	"teamcity",
	"teamcity_token",
	"teamcity_api",
	"teamcity_url",
	"app/rest",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TeamCity }

func (Scanner) Keywords() []string { return []string{"teamcity"} }

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
			DetectorType: detectors.TeamCity,
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

// Verify checks the token as a TeamCity bearer credential against
// GET {apiBase}/app/rest/server. When apiBase is unset there is no host to
// reach, so verification is a no-op (false, nil) — the detector still surfaces
// the token unverified. A transport error (e.g. wrong host) is returned as the
// error so the engine records VerificationErr rather than a false negative.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	base := strings.TrimRight(apiBase, "/")
	if base == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/app/rest/server", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, acceptCodes, rejectCodes)
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
