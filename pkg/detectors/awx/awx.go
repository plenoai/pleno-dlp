// Package awx detects AWX / Ansible Tower / Ansible Automation Platform
// OAuth2 Bearer tokens (40-char base62 near `awx_token` / `tower_token`).
//
// AWX runs on customer-controlled hosts so the verify endpoint isn't a
// fixed SaaS URL. The matched token is itself the OAuth2 Bearer credential
// the AWX REST API accepts, so verification fires only when an apiBase
// override pointing at the operator's AWX/Tower host is supplied; it
// hits `GET /api/v2/me/` (the authenticated-user endpoint) with the token
// as a Bearer header. Without apiBase the detector surfaces under
// --unverified-results; keyword gating + token shape carry the
// false-positive bound.
package awx

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)

var contextKeywords = []string{
	"awx_token",
	"awx_api",
	"tower_token",
	"tower_api",
	"ansible_tower",
	"ansible_automation",
	"awx_oauth",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWX }

func (Scanner) Keywords() []string { return []string{"awx", "ansible_tower", "ansible_automation"} }

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
			DetectorType: detectors.AWX,
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
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// Verify checks the candidate AWX OAuth2 token against the operator's
// AWX/Tower host. It no-ops (per repo policy this still counts as a
// verifying detector) when no apiBase override is configured, since AWX
// is self-hosted and the host is neither in the chunk nor derivable from
// the opaque token. The /api/v2/me/ endpoint returns 200 for an
// authenticated token and 401/403 otherwise; 5xx/429 are surfaced as
// transient verification errors rather than a "not valid" verdict.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2/me/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, transportErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, transportErr, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
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
