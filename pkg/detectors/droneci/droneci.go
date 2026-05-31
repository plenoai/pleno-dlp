// Package droneci detects Drone CI personal access tokens (24-32 char
// alnum) bound to an explicit drone-prefixed assignment anchor.
//
// Verify is intentionally not implemented (class b, unverified-by-design).
// Drone CI is self-hosted; the API endpoint (GET /api/user with a Bearer
// token) depends on the operator's server URL (e.g. drone.example.com)
// which is rarely co-located with the token in code. Bolting verify
// against an arbitrary operator apiBase would route foreign-provider
// tokens to a foreign host and yield meaningless results, so we surface
// the leak unverified-by-design and let reviewers rotate.
//
// The token shape `[A-Za-z0-9]{24,32}` is extremely generic — it matches
// almost any unrelated key/ID/commit-SHA that appears in a CI config that
// merely mentions "drone". To suppress that noise we require:
//   - an assignment-style anchor binding the token to a drone-prefixed
//     key (DRONE_TOKEN=, drone_token:, drone_secret=, ...), and
//   - a minimum Shannon entropy, and
//   - rejection of all-same-char and pure-hex (commit-SHA) lookalikes.
package droneci

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// assignmentRe binds a 24-32 char alnum token to an explicit
// drone-prefixed key via an assignment operator (`=`, `:`). This is the
// load-bearing anchor: a free-floating token near the bare word "drone"
// no longer qualifies. Matches e.g.
//
//	DRONE_TOKEN=AbCdEf0123456789AbCdEf01
//	drone_token: AbCdEf0123456789AbCdEf01
//	drone-secret = "AbCdEf0123456789AbCdEf01"
//	DRONE_SERVER_TOKEN: AbCdEf0123456789AbCdEf01
//
// The key must start with `drone` and be one of the known credential
// suffixes (token / secret / server[_token] / pat / api[_key]).
var assignmentRe = regexp.MustCompile(`(?i)` +
	`drone[_\-]?(?:server[_\-]?)?(?:token|secret|pat|api[_\-]?key)` +
	`["']?\s*[:=]\s*["']?` +
	`([A-Za-z0-9]{24,32})\b`)

// pureHexRe matches tokens that look like a hex commit-SHA / build id
// rather than a real Drone PAT (which is mixed-case alnum).
var pureHexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// minEntropy drops repetitive / low-information lookalikes (e.g. runs of
// the same char). 3.0 bits/char is the sane floor for a 24-char alnum
// token; real Drone PATs comfortably clear it.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DroneCI }

func (Scanner) Keywords() []string { return []string{"drone"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := assignmentRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m[1])
		if _, dup := seen[token]; dup {
			continue
		}
		if !isPlausibleToken(token) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.DroneCI,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isPlausibleToken rejects shapes that are syntactically a 24-32 char
// alnum string but are not real Drone PATs: low-entropy/repetitive
// strings and pure-hex commit-SHA-style identifiers.
func isPlausibleToken(token string) bool {
	if pureHexRe.MatchString(token) {
		return false
	}
	if allSameChar(token) {
		return false
	}
	return detectors.HasMinEntropy(token, minEntropy)
}

func allSameChar(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
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
