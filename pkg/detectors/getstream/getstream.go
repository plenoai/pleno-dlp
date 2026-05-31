// Package getstream detects Stream (getstream.io) chat / activity feed
// credentials — a paired api_key + api_secret (each 12+ alphanumeric) near
// a Stream credential-context keyword.
//
// Unverified-by-design: Stream's server-side REST auth does not accept the
// raw api_secret. Every server call requires a JWT signed HMAC-SHA256 with
// the api_secret, sent as `Authorization: <jwt>` + `Stream-Auth-Type: jwt`
// and `?api_key=<key>`. There is no mirrorable trufflehog upstream detector
// and no pinned reference for the exact server-token claims payload, so a
// live Verify cannot be written without risking a malformed-but-accepted
// shape yielding a false Verified=true. Hence: surface unverified only.
// Raw carries the api_key, RawV2 carries the api_secret.
//
// FP control: the api_key / api_secret token shape (12+ alnum) is extremely
// generic — config values, Git SHAs, dictionary-ish identifiers all match.
// We gate hard:
//  1. a *credential-context* anchor must be within radius of the token
//     (a bare `getstream.io` / `stream.io` / `streamio` URL or identifier is
//     NOT enough — it would pair arbitrary adjacent tokens);
//  2. both paired tokens must clear a Shannon-entropy floor;
//  3. single-character-class runs (all-lowercase / all-uppercase / all-digit)
//     and hex-only 40-char Git-SHA shapes are rejected.
package getstream

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{12,80})\b`)

// hexShaRe matches a 40-char hex run (Git SHA-1) — a common neighbour of a
// `stream.io migration` commit message that must never be paired as a credential.
var hexShaRe = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// credAnchorRe is the *credential-context* anchor. A bare Stream URL/identifier
// (`getstream.io`, `stream.io`, `stream_io`, `streamio`) is deliberately
// excluded: those appear in docs, import paths, table names and commit
// messages with no real secret nearby, and pairing on them grabs any two
// adjacent alnum identifiers. We require an explicit key/secret/app marker.
var credAnchorRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`stream[_\-]?api[_\-]?key` +
	`|stream[_\-]?api[_\-]?secret` +
	`|getstream[_\-]?(?:api[_\-]?key|api[_\-]?secret|secret|token|key)` +
	`|stream[_\-]?(?:secret|app[_\-]?id|app[_\-]?secret)` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GetStream }

func (Scanner) Keywords() []string {
	return []string{"getstream", "stream_io", "stream.io", "streamio"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	anchors := credAnchorRe.FindAllIndex(data, -1)
	if len(anchors) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		key := string(data[h[2]:h[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !plausibleCredential(key) || !nearKeyword(anchors, h[2], h[3]) {
			continue
		}
		var sec string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand != key && plausibleCredential(cand) && nearKeyword(anchors, h2[2], h2[3]) {
				sec = cand
				break
			}
		}
		if sec == "" {
			continue
		}
		seen[key] = struct{}{}
		seen[sec] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.GetStream,
			Raw:          []byte(key),
			RawV2:        []byte(sec),
			Redacted:     redact(key),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// plausibleCredential rejects token shapes that match the loose alnum regex
// but cannot be a randomly-generated Stream key/secret:
//   - low Shannon entropy (repeated chars, dictionary words, zero runs);
//   - single-character-class runs (all lowercase / all uppercase / all digit
//     — real Stream credentials are high-variety random strings);
//   - 40-char hex Git SHA shapes.
func plausibleCredential(t string) bool {
	if hexShaRe.MatchString(t) {
		return false
	}
	if !detectors.HasMinEntropy(t, 3.0) {
		return false
	}
	return charClassCount(t) >= 2
}

func charClassCount(s string) int {
	var lower, upper, digit bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	n := 0
	if lower {
		n++
	}
	if upper {
		n++
	}
	if digit {
		n++
	}
	return n
}

// nearKeyword keeps a tighter radius than the old 96-byte window: a real
// credential lives on or adjacent to its `stream_api_key=` marker, so 48
// bytes is enough and roughly halves the pairing surface.
func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 48
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
