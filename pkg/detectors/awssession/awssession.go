// Package awssession detects AWS temporary session credential triples
// (ASIA<16>) — access-key-id with paired secret access key and session token.
//
// Verification is intentionally not performed inline. STS GetCallerIdentity is
// the natural probe, but session tokens are region- and time-scoped: a token
// minted for an arbitrary tenant against an arbitrary region cannot be
// confirmed without context the scanner doesn't have. Probing also leaves an
// audit-log trail in the credential owner's account, which we do not want to
// emit silently. So awssession surfaces unverified-by-design and the engine
// renders it under --unverified-results.
//
// The token shape is the canonical signal: ASIA[0-9A-Z]{16} for the id, the
// 40-char secret-access-key shape from the existing AWS detector, plus a
// session token (FwoG…/IQoJb3JpZ2luX2VjE…) that is base64-ish and ~200 chars
// long. The session-token shape is what disambiguates this detector from the
// long-lived AKIA path owned by `pkg/detectors/aws`.
package awssession

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	// ASIA<16> is the temporary credential prefix. AKIA is owned by the
	// long-lived AWS detector and is intentionally excluded here so the two
	// don't double-fire on the same id.
	idRe = regexp.MustCompile(`\b(ASIA[0-9A-Z]{16})\b`)
	// 40-char base64-ish run, same shape as the long-lived secret access
	// key. We anchor with non-base64 surrounding bytes so adjacent tokens
	// don't merge into a single capture.
	secretRe = regexp.MustCompile(`[^A-Za-z0-9+/]([A-Za-z0-9+/]{40})[^A-Za-z0-9+/]`)
	// Session tokens are base64 with `+/=` and run 100..1024 chars. Go's
	// regexp engine caps the upper repetition bound at 1000, so we use
	// 100..1000 — that still covers every Amazon-issued session token
	// today.
	sessionRe = regexp.MustCompile(`[^A-Za-z0-9+/=]([A-Za-z0-9+/=]{100,1000})[^A-Za-z0-9+/=]`)
)

var contextKeywords = []string{"aws_session_token", "session_token", "sessiontoken", "x-amz-security-token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWSSession }

// ASIA prefilters cheaply; session_token catches cases where the id is on a
// separate line far from the prefix.
func (Scanner) Keywords() []string { return []string{"ASIA", "session_token"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	sessions := sessionRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idMatches))
	seen := map[string]struct{}{}
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		// The session-token co-occurrence keyword is mandatory: ASIA can
		// otherwise show up in benign IAM policy fixtures. Without it we
		// emit nothing.
		if !nearKeyword(lower, m[2], m[3]) && !haveNearbySession(m[2], data, sessions) {
			continue
		}
		secret, _ := nearestRun(m[2], data, secrets, 512)
		session, _ := nearestRun(m[2], data, sessions, 1024)

		res := detectors.Result{
			DetectorType: detectors.AWSSession,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
		}
		if secret != "" {
			res.RawV2 = []byte(secret)
		}
		if session != "" {
			res.ExtraData["session_token_prefix"] = redact(session)
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func haveNearbySession(idStart int, data []byte, sessions [][]int) bool {
	for _, sm := range sessions {
		if abs(sm[2]-idStart) <= 1024 {
			return true
		}
	}
	_ = data
	return false
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
