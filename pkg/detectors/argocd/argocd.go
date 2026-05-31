// Package argocd detects Argo CD API tokens (JWT-shaped). Argo CD tokens are
// standard JWTs minted by the API server, so the regex shape collides with
// the generic JWT detector — we gate hard on the `argocd_token` /
// `argocd_auth` / `argocd_session` keyword window so we only surface tokens
// that the surrounding text identifies as Argo CD.
//
// Verification: the matched Raw secret is the genuine Argo CD API token — a JWT
// used directly as a bearer credential (`Authorization: Bearer <token>`). We
// verify it against the Argo CD API server's `GET /api/v1/account` endpoint.
// Argo CD is always self-hosted per-customer, so the API host is neither fixed
// nor derivable from the token (the JWT `iss` claim is the literal string
// "argocd", not a URL). Verify therefore no-ops unless the operator supplies an
// apiBase override — the well-established self-hosted apiBase-override pattern.
// Status discrimination:
//   - 200 -> Verified=true (token authenticated, account readable)
//   - 403 -> Verified=true (token authenticated but lacks the accounts,get RBAC
//     permission; a forged/expired token can never reach 403, only a real
//     authenticated identity can, so 403 still proves authenticity)
//   - 401 -> Verified=false (bearer token rejected)
//   - 429 / 5xx -> transient (surfaced as VerificationErr, scan continues)
package argocd

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the Argo CD API server host. Argo CD is self-hosted, so this has
// no real default — verification is a no-op unless an operator overrides it
// (also overridden by tests via httptest.Server). The apiBase-override pattern
// is the repo convention for self-hosted providers.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK, http.StatusForbidden}
	verifyRejectCodes = []int{http.StatusUnauthorized}
)

// JWT shape: header.payload.signature, base64url segments separated by dots.
var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})\b`)

var contextKeywords = []string{
	"argocd_token",
	"argocd_auth",
	"argocd_session",
	"argocd.token",
	"argocd_api_token",
	"argo_cd_token",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ArgoCD }

func (Scanner) Keywords() []string { return []string{"argocd"} }

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
			DetectorType: detectors.ArgoCD,
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

// Verify checks the token against the Argo CD API server's account endpoint.
// It no-ops (returns false, nil) unless an operator has supplied an apiBase
// override, because Argo CD is self-hosted and the host cannot be derived from
// the token. See package doc for status-code semantics.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
