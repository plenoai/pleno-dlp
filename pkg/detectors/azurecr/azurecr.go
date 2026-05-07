// Package azurecr detects Azure Container Registry refresh / access tokens.
// ACR uses long JWT-style tokens (`<base64url>.<base64url>.<base64url>`)
// fetched via /oauth2/token from a per-registry host (`<name>.azurecr.io`).
// Gated on the `azurecr` keyword window so the broad JWT shape doesn't
// collide with the generic JWT detector. Unverified by design — the
// registry hostname isn't recoverable from the token alone, so a verified
// path would require user-supplied configuration.
package azurecr

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,400}\.[A-Za-z0-9_\-]{10,800}\.[A-Za-z0-9_\-]{10,400})\b`)

var contextKeywords = []string{"azurecr", ".azurecr.io", "acr_token", "acr_refresh", "acr_access", "acr_password"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureContainerRegistry }

func (Scanner) Keywords() []string { return []string{"azurecr", "acr_"} }

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
			DetectorType: detectors.AzureContainerRegistry,
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
