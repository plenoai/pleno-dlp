// Package awx detects AWX / Ansible Tower / Ansible Automation Platform
// OAuth2 Bearer tokens (30-char base62 near `awx_token` / `tower_token`).
//
// Token format is authoritative: AWX issues OAuth2 tokens via Django OAuth
// Toolkit, which delegates to oauthlib's
// `generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET)` — a 30-char
// base62 (`[A-Za-z0-9]`) random string. See oauthlib/common.py and the AWX
// token-auth docs whose example tokens are both exactly 30 chars
// (`9epHOqHhnXUcgYK8QanOmUQPSgX92g`). The prior 40-char pin never matched a
// real token; the length is now corrected to 30 and gated by entropy.
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

// 30 base62 chars — the oauthlib generate_token default that AWX/Tower uses.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{30})\b`)

// minEntropy rejects low-information 30-char runs (padded hex, repeated
// fragments, structured identifiers) that clear the bare regex but lack the
// randomness of an oauthlib-generated token. base62 caps near ~5.95 bits/char;
// 3.5 is the documented floor for no-prefix fixed-length high-variety tokens.
const minEntropy = 3.5

// contextRe is the windowed assignment-anchor gate. The prior bare
// strings.Contains over radius 256 matched any incidental "awx_api" substring
// far from the token; this arm regex requires an AWX/Tower token/key/secret
// assignment shape, and the bare keywords stay in Keywords() as the prefilter.
var contextRe = regexp.MustCompile(`(?i)(awx|tower|ansible[_-]?(tower|automation))[_-]?(api[_-]?)?(token|key|secret|oauth)`)

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
		if !detectors.HasMinEntropy(token, minEntropy) {
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
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	return contextRe.MatchString(window)
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
