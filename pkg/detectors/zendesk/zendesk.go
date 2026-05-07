// Package zendesk detects Zendesk API tokens (40 alphanumerics near
// `zendesk` keyword) optionally paired with the operator email Zendesk
// requires for Basic auth.
//
// Verify is intentionally not performed. Zendesk's API endpoint host is
// tenant-scoped (`<subdomain>.zendesk.com`) and the subdomain is rarely
// embedded next to the token in source. Probing a guessed host risks
// wrong-tenant audit-log entries. So zendesk surfaces unverified-by-design
// and the engine renders it under --unverified-results.
package zendesk

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Zendesk API tokens are documented as 40 base62 chars.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)

// RFC5322-ish email shape — kept conservative so we don't chase malformed
// addresses. We pair the operator email with the token via Basic auth.
var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b`)

// Optional subdomain capture for ExtraData.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.zendesk\.com)\b`)

var contextKeywords = []string{"zendesk"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zendesk }

func (Scanner) Keywords() []string { return []string{"zendesk"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	emails := emailRe.FindAllSubmatchIndex(data, -1)
	host := hostRe.FindString(string(data))
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// 40 alnum is far too generic — co-occurrence is mandatory.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = strings.ToLower(host)
		}
		res := detectors.Result{
			DetectorType: detectors.Zendesk,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if email, ok := nearestRun(h[2], data, emails, 256); ok {
			res.RawV2 = []byte(email)
			res.ExtraData["email"] = email
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearestRun(idStart int, data []byte, runs [][]int, maxDistance int) (string, bool) {
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range runs {
		start, end := sm[2], sm[3]
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
