// Package jslogincallsecret detects a credential passed as a bare
// positional argument to a JS/TS SDK authentication call, e.g.:
//
//	conn.login('user@example.com', 'salesforcepassword', function(err, res) {
//
// This is the shape leaky-repo's own web/js/salesforce.js fixture
// actually uses (jsforce's `Connection#login(username, password,
// callback)`). It is a deliberate pivot away from issue #175's
// original framing of this shape as a "known-key JS assignment"
// (`password`/`token`/`securityToken` object keys or `var` names): the
// real fixture has no such keyword anywhere in the file — the
// credential is the second positional argument, identified only by its
// position next to an email-shaped first argument.
//
// That original framing is, for the parts of it that do apply, already
// covered: hardcodedpassword's `key = value` / `key: value` regexes are
// language-agnostic and already match `password = '...'` /
// `password: '...'` wherever they appear, including in `.js` files —
// keying on `password`/`passwd`/`pwd`. Extending that keyword set to
// bare `token` or `securityToken` was considered and rejected: `token`
// alone is extremely common on non-secret values (CSRF tokens, request
// IDs, pagination cursors, UI state) and would be a significant new
// noise source for a keyword-only, non-entropy-gated detector — the
// same trade-off APIKeyAssignment's package doc (batch 2) already
// argues against for a bare `key` keyword.
//
// loginCallRe requires two adjacent conditions to fire: a call to one
// of a small set of auth-shaped method names, and a first argument that
// looks like an identity (contains `@`, the same email-shape heuristic
// as the second positional arg's neighbor). Bare `.connect(...)` calls
// without an email-shaped first argument — overwhelmingly the common
// case for non-auth `.connect()` usage (sockets, DB pools, event
// listeners) — never match.
//
// Verify is deliberately not implemented (class b): the target host is
// whatever instance the SDK's client object was configured against
// elsewhere in the codebase, not present in this chunk.
package jslogincallsecret

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// loginCallRe matches `<expr>.login(`/`.authenticate(`/`.signIn(` (or
// `.signin(`) with a quoted, email-shaped first argument and a quoted
// second argument.
// Go's RE2 has no backreferences, so the opening/closing quote is not
// required to match per argument (a mismatched-quote literal is not
// valid JS and essentially never appears in real files).
var loginCallRe = regexp.MustCompile(
	`(?i)\.(?:login|authenticate|signIn)\s*\(\s*['"]([^'"\r\n]+@[^'"\r\n]+)['"]\s*,\s*['"]([^'"\r\n]{4,128})['"]`,
)

var placeholders = map[string]struct{}{
	"password":    {},
	"changeme":    {},
	"change_me":   {},
	"example":     {},
	"placeholder": {},
	"secret":      {},
	"test":        {},
	"testing":     {},
	"dummy":       {},
	"sample":      {},
	"none":        {},
	"null":        {},
	"x":           {},
	"xxx":         {},
	"":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JSLoginCallSecret }

func (Scanner) Keywords() []string {
	return []string{"login(", "authenticate(", "signin("}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range loginCallRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		identity, secret := m[1], m[2]
		if isPlaceholder(secret) {
			continue
		}
		key := identity + ":" + secret
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.JSLoginCallSecret,
			Raw:          []byte(secret),
			Redacted:     redact(secret),
			ExtraData: map[string]string{
				"identity": identity,
			},
			Severity: detectors.SeverityHigh,
		})
	}

	return out, nil
}

func redact(s string) string {
	if len(s) <= 4 {
		return "..."
	}
	return s[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
