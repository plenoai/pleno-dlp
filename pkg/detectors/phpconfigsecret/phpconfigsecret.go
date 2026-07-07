// Package phpconfigsecret detects two PHP config-file credential
// shapes that pkg/detectors/hardcodedpassword structurally cannot see:
//
//  1. `define('KEY', 'value')` constant declarations, as
//     `wp-config.php` uses for DB_PASSWORD and its eight AUTH_KEY/SALT
//     constants. hardcodedpassword's assignment regex requires a literal
//     `=`; PHP's `define()` call syntax uses comma-separated arguments,
//     not `=`, so it never matches.
//  2. `$variable = 'value';` assignments whose variable name embeds a
//     credential keyword (password/passwd/pwd/secret) directly against
//     another identifier with no separator — e.g. `$dbpasswd`.
//     hardcodedpassword's keyword boundary requires the keyword not be
//     preceded by a letter, so `db` immediately touching `passwd` (no
//     underscore) fails that boundary and is never matched there.
//
// The `define()` form is gated by a known-key allowlist
// (knownDefineKeys below) rather than generic substring matching:
// `AUTH_KEY` and `NONCE_SALT` only contain "key"/"salt", and matching
// on those generically would fire on every unrelated PHP `define()`
// call in existence (`CACHE_KEY_PREFIX`, `SALT_ROUNDS`, ...). The `$var`
// form keeps hardcodedpassword's narrower password/passwd/pwd/secret
// substring approach since the variable-name signal there is already
// specific.
//
// FP calibration note: WordPress auth salts are drawn from the full
// printable-ASCII range, so they legitimately contain bare `<`, `>`,
// `{`, `}` as random noise. Unlike hardcodedpassword's templating gate
// (which rejects bare `<`/`>`), this detector only rejects genuine
// two-character template markers (`${`, `{{`, `<%`, `%{`) — a bare `<`
// or `>` occurring by chance in 71 bytes of random punctuation is
// common and must not be treated as a template placeholder.
//
// Verify is deliberately not implemented (class b): these are
// offline config credentials with no endpoint in the matched chunk.
package phpconfigsecret

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// phpDefineRe matches `define('KEY', 'value')` / `define("KEY", "value")`
// with optional whitespace around the parens/comma, as PHP-CS-Fixer and
// generatewp.com-style generators both produce.
var phpDefineRe = regexp.MustCompile(
	`(?i)define\s*\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*(?:'([^']*)'|"([^"]*)")\s*\)`,
)

// phpVarRe matches `$xxxpasswordxxx = 'value';` PHP variable assignment,
// where the variable name contains one of the credential keywords with
// no separator required (covers `$dbpasswd` as well as `$db_password`).
var phpVarRe = regexp.MustCompile(
	`(?i)\$([a-z0-9_]*(?:password|passwd|pwd|secret)[a-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)")`,
)

// knownDefineKeys are the WordPress/Laravel/common-framework constant
// names this detector recognizes as credential-bearing. Compared
// case-insensitively. Anything else (DB_NAME, DB_USER, DB_HOST, ABSPATH,
// TABLE_PREFIX, ...) is informative config, not a secret, and is left
// alone.
var knownDefineKeys = map[string]struct{}{
	"db_password":       {},
	"db_pass":           {},
	"db_passwd":         {},
	"database_password": {},
	"auth_key":          {},
	"secure_auth_key":   {},
	"logged_in_key":     {},
	"nonce_key":         {},
	"auth_salt":         {},
	"secure_auth_salt":  {},
	"logged_in_salt":    {},
	"nonce_salt":        {},
	"secret_key":        {},
	"api_key":           {},
	"api_secret":        {},
	"app_key":           {},
	"app_secret":        {},
	"jwt_secret":        {},
	"encryption_key":    {},
	"session_secret":    {},
	"admin_password":    {},
}

var placeholders = map[string]struct{}{
	"password":    {},
	"passwd":      {},
	"pass":        {},
	"pwd":         {},
	"secret":      {},
	"changeme":    {},
	"change_me":   {},
	"changeit":    {},
	"example":     {},
	"placeholder": {},
	"admin":       {},
	"admin123":    {},
	"root":        {},
	"test":        {},
	"testing":     {},
	"dummy":       {},
	"sample":      {},
	"null":        {},
	"none":        {},
	"true":        {},
	"false":       {},
	"":            {},
	"x":           {},
	"xxx":         {},
	"1234":        {},
	"12345":       {},
	"123456":      {},
	"letmein":     {},
	"qwerty":      {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

// templateMarkers are genuine template-variable delimiters. Only exact
// two-character sequences — see the package doc comment for why a bare
// `<`/`>`/`{`/`}` must not be treated as a marker here.
var templateMarkers = []string{"${", "{{", "<%", "%{"}

func hasTemplateMarker(v string) bool {
	for _, m := range templateMarkers {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PHPConfigSecret }

func (Scanner) Keywords() []string {
	return []string{
		"define(", "password", "passwd", "pwd", "secret",
		"auth_key", "secure_auth_key", "logged_in_key", "nonce_key",
		"auth_salt", "secure_auth_salt", "logged_in_salt", "nonce_salt",
	}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(key, val string) {
		val = strings.TrimSpace(val)
		if len(val) < 4 {
			return
		}
		if hasTemplateMarker(val) {
			return
		}
		if isPlaceholder(val) {
			return
		}
		dedupKey := key + "\x00" + val
		if _, dup := seen[dedupKey]; dup {
			return
		}
		seen[dedupKey] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PHPConfigSecret,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"key": key,
			},
			Severity: detectors.SeverityHigh,
		})
	}

	for _, m := range phpDefineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 4 {
			continue
		}
		key := m[1]
		if _, known := knownDefineKeys[strings.ToLower(key)]; !known {
			continue
		}
		val := m[2]
		if val == "" {
			val = m[3]
		}
		add(key, val)
	}

	for _, m := range phpVarRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 4 {
			continue
		}
		key := "$" + m[1]
		val := m[2]
		if val == "" {
			val = m[3]
		}
		add(key, val)
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
