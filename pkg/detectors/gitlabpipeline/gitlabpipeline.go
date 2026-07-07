// Package gitlabpipeline detects GitLab pipeline trigger tokens (40-char hex
// or UUID-shaped). Trigger tokens are distinct from PATs (handled by gitlab)
// and project deploy tokens (handled by gitlabdeploy): they grant *only* the
// right to run a pipeline on the owning project, but a malicious pipeline can
// leak any CI variable.
//
// Unverified-by-design (class b). Verification is infeasible: the real
// endpoint POST /api/v4/projects/:id/trigger/pipeline (a) needs a project id
// that is neither encoded in the token nor reliably derivable from the chunk,
// (b) needs a host that is absent (gitlab.com vs self-hosted), and (c) is
// DESTRUCTIVE — a successful call actually runs a CI pipeline, and a 404
// cannot distinguish an invalid token from an unknown project, so any probe
// risks both a side effect and a false Verified=true. GitLab exposes no
// read-only validation endpoint for trigger tokens.
//
// Because a bare 40-char lowercase hex is indistinguishable from a Git SHA-1
// and a UUID is indistinguishable from any resource id, the detector relies on
// a tight assignment-form anchor (the token must be the RHS of a trigger
// keyword within a small window), a Shannon-entropy gate, and a git/commit/sha
// negative exclusion for the hex branch.
package gitlabpipeline

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 40-char lowercase hex branch (vs. UUID). Used to decide whether the Git-SHA
// negative exclusion applies.
var hex40Re = regexp.MustCompile(`^[a-f0-9]{40}$`)

// Assignment-form anchor: the token must appear as the RHS of a recognised
// trigger keyword (with an optional small gap for quoting / spacing) rather
// than merely co-occurring in a 256-byte vicinity. Anchored so that an
// unrelated UUID/SHA near a trigger_token key holding a *different* value is
// not cross-matched.
var assignRe = regexp.MustCompile(
	`(?i)(?:pipeline_trigger|trigger_token|ci_pipeline_trigger|gitlab_trigger)["' ]{0,4}[:=]["' ]{0,4}([a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,
)

// Vicinity words that mark a 40-hex value as a Git object / checksum rather
// than a trigger token. Only consulted on the hex branch.
var gitContextWords = []string{"git", "commit", "sha", "checksum", "revision", "sha1", "sha1sum"}

// minEntropy drops low-entropy / patterned hex, e.g. repeated or sequential
// SHAs and placeholder-looking strings.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitLabPipeline }

func (Scanner) Keywords() []string { return []string{"pipeline_trigger", "trigger_token"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	// Cheap prefilter: bail before regex unless an assignment-form anchor
	// can possibly exist.
	hits := assignRe.FindAllSubmatchIndex(data, -1)
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
		// Git-SHA negative exclusion: a bare 40-char lowercase hex is
		// indistinguishable from a commit SHA, so reject when the immediate
		// vicinity carries git/commit/sha/checksum/revision context.
		if hex40Re.MatchString(token) && nearGitContext(lower, h[0], h[1]) {
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

// nearGitContext reports whether a git/commit/sha-style word appears within a
// tight window around the match. Smaller than the old 256-byte vicinity so a
// SHA elsewhere in the same file doesn't taint a real trigger assignment.
func nearGitContext(lower string, start, end int) bool {
	const radius = 40
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, w := range gitContextWords {
		if strings.Contains(window, w) {
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
