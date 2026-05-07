// Package sonatypenexus detects Sonatype Nexus Repository user tokens
// (NXRT-<base64url>) gated on the `nexus` keyword window. Nexus is self-
// hosted, so the server URL isn't in the chunk — surfaces unverified-by-
// design.
package sonatypenexus

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Nexus user tokens are emitted by the /service/rest/v1/security/user-tokens
// endpoint and follow the `NXRT-<id>-<token>` shape. The detector is
// permissive on the suffix to capture both `NXRT-` and the rarer `NPA-` /
// raw-token forms shipped by older Nexus versions.
var tokenRe = regexp.MustCompile(`\b(NXRT-[A-Za-z0-9_=\-]{16,})\b`)

var contextKeywords = []string{"nexus", "sonatype", "nexus_user_token", "nexus_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SonatypeNexus }

func (Scanner) Keywords() []string { return []string{"nexus", "sonatype", "NXRT-"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
			DetectorType: detectors.SonatypeNexus,
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
