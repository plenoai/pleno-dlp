// Package gitlabpipeline detects GitLab pipeline trigger tokens (40-char hex
// or UUID-shaped) gated on the `pipeline_trigger` keyword. Trigger tokens are
// distinct from PATs (handled by gitlab) and project deploy tokens (handled
// by gitlabdeploy): they grant *only* the right to run a pipeline on the
// owning project, but a malicious pipeline can leak any CI variable. The
// detector is unverified-by-design — verifying requires the project id and
// would actually run a pipeline, which is a destructive side effect.
package gitlabpipeline

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 40-char hex (legacy) OR uuid (newer trigger tokens).
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

var contextKeywords = []string{
	"pipeline_trigger",
	"trigger_token",
	"ci_pipeline_trigger",
	"gitlab_trigger",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitLabPipeline }

func (Scanner) Keywords() []string { return []string{"pipeline_trigger", "trigger_token"} }

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
			DetectorType: detectors.GitLabPipeline,
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
