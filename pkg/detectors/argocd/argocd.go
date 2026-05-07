// Package argocd detects Argo CD API tokens (JWT-shaped). Argo CD tokens are
// standard JWTs minted by the API server, so the regex shape collides with
// the generic JWT detector — we gate hard on the `argocd_token` /
// `argocd_auth` / `argocd_session` keyword window so we only surface tokens
// that the surrounding text identifies as Argo CD. Argo CD is typically
// self-hosted (per-customer host), so verification is unverified-by-design.
package argocd

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
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

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		out = append(out, detectors.Result{
			DetectorType: detectors.ArgoCD,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
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

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
