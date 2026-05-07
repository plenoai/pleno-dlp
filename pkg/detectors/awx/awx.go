// Package awx detects AWX / Ansible Tower / Ansible Automation Platform
// OAuth2 Bearer tokens (40-char base62 near `awx_token` / `tower_token`).
//
// AWX runs on customer-controlled hosts so the verify endpoint isn't a
// fixed SaaS URL. The detector surfaces under --unverified-results by
// design; keyword gating + token shape carry the false-positive bound.
package awx

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

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
			DetectorType: detectors.AWX,
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
