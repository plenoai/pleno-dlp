// Package bugsnag detects Bugsnag API keys (32-hex, lowercase) — the client
// `BUGSNAG_API_KEY` notifier/project key.
//
// Verify is intentionally NOT implemented (unverified-by-design). The value
// this detector matches is the per-project notifier/ingest key, not a personal
// auth token. Bugsnag's read API (`GET /user`, `/projects`, `/organizations`
// on api.bugsnag.com) authenticates with `Authorization: token <PERSONAL-AUTH-
// TOKEN>` — a different credential — so a live project key would return 401
// there (false Verified=false). The only endpoints the project key actually
// authorizes (`/notify`, `/build`, session ingest) are event WRITES; probing
// them would inject synthetic data into the owner's project, a destructive
// side effect repo policy forbids during a scan. So bugsnag surfaces
// unverified-by-design (class b), the same trap as a Sentry DSN.
//
// Because the token shape (`[a-f0-9]{32}`) is exactly an MD5 hash, this
// detector leans hard on (1) an assignment-anchored primary regex, (2) a
// tight (~40 byte) vicinity fallback, (3) negative exclusion of hash/checksum
// context, and (4) a Shannon-entropy floor to drop lookalike digests.
package bugsnag

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Primary: an explicit bugsnag key assignment. The key MUST be introduced by a
// bugsnag-flavoured identifier and an assignment/colon operator, e.g.
//
//	BUGSNAG_API_KEY=<hex>     bugsnag_key: <hex>     bugsnagApiKey = "<hex>"
//
// This is the high-confidence path and is checked first.
var assignRe = regexp.MustCompile(`(?i)bugsnag[_-]?(?:api[_-]?)?key["'\s:=]{1,4}([a-f0-9]{32})`)

// Fallback shape: a bare 32-hex token, qualified only when it sits immediately
// adjacent to a bugsnag context token (see nearKeyword) AND is not in a
// hash/checksum context (see looksLikeHashContext).
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

// Context tokens that must appear within the tight vicinity for a bare hit.
var contextKeywords = []string{"bugsnag"}

// Tokens that, when adjacent to a 32-hex value, mark it as a digest/checksum
// rather than a credential. Bugsnag npm packages ship integrity hashes in
// lockfiles, sourcemaps carry content hashes, CI logs carry ETags — all are
// 32-hex MD5 shapes that co-occur with the word "bugsnag".
var hashContextKeywords = []string{
	"integrity", "sha1", "sha256", "sha512", "md5", "etag",
	"checksum", "hash", "cache_key", "cache-key", "cachekey", "digest",
}

// 32-hex over a 16-symbol alphabet caps at 4.0 bits/char. Real keys land near
// the ceiling; all-zero / repeated / low-variety MD5 lookalikes fall well
// below. 3.0 drops the degenerate cases without clipping genuine keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bugsnag }

func (Scanner) Keywords() []string { return []string{"bugsnag"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}

	emit := func(token string, start, end int) {
		if _, dup := seen[token]; dup {
			return
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
			return
		}
		if looksLikeHashContext(lower, start, end) {
			return
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Bugsnag,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}

	// Primary, assignment-anchored path. High confidence — no vicinity check
	// needed, the key is syntactically bound to a bugsnag identifier.
	for _, h := range assignRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		emit(token, h[2], h[3])
	}

	// Fallback: bare 32-hex, only when immediately adjacent to a bugsnag token.
	for _, h := range tokenRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		emit(token, h[2], h[3])
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword requires a context token within a tight 40-byte radius — the key
// must sit immediately next to a bugsnag mention, not merely co-occur in the
// same chunk. Wide radii let an unrelated MD5 in a lockfile match a distant
// "bugsnag" string.
func nearKeyword(lower string, start, end int) bool {
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
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// looksLikeHashContext rejects a 32-hex value adjacent to digest/checksum
// vocabulary. Uses the same tight radius so only the directly-surrounding
// field name counts.
func looksLikeHashContext(lower string, start, end int) bool {
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
	for _, kw := range hashContextKeywords {
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
