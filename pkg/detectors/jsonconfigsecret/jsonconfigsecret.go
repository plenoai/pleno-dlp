// Package jsonconfigsecret detects `"key": "value"` credential pairs in
// JSON config files whose key names are drawn from a small
// credential-shaped vocabulary (password/passwd/pwd/passphrase/secret/
// api_key/apikey, or the bare key "pass"). This is the common shape
// shared by SFTP-client editor configs (Sublime's sftp-config.json,
// Atom's .ftpconfig, .remote-sync.json, VS Code's .vscode/sftp.json),
// generic deploy configs (cloud/heroku.json's HEROKU_API_KEY,
// deployment-config.json), and DB-client configs (Robomongo's
// db/robomongo.json, whose credentials live under
// connections[].credentials[].userPassword) — none of these tools
// share a schema, but they all serialize the credential as a plain
// quoted JSON string value under a key containing one of those words.
//
// Matching is regex-based over raw bytes rather than a full JSON
// parse (same approach as phpconfigsecret's `$var = 'value'` matcher):
// these files are consumed as flat text by the scanner, and a full
// unmarshal would need a strict schema for a build-your-own JSON blob
// with no fixed shape.
//
// The bare key "pass" is matched as an exact key (not a substring)
// deliberately — "pass" is common enough as a substring of unrelated
// English words (compass, bypass, passenger, passport) that a
// substring match would produce real noise; the longer creds vocabulary
// words below are specific enough to match as substrings the way
// phpconfigsecret already does for its $var form.
//
// Verify is deliberately not implemented (class b): these are offline
// config credentials — the host they authenticate against, when
// present at all, is data-controlled and arbitrary (SFTP/deploy
// targets), not a fixed provider endpoint.
package jsonconfigsecret

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// jsonKeyValueRe matches a JSON string key/value pair whose key either
// equals "pass" exactly or contains one of the longer credential
// vocabulary words as a substring (case-insensitive), covering
// camelCase (userPassword), snake_case (db_password), and
// SCREAMING_SNAKE (HEROKU_API_KEY) key styles alike.
var jsonKeyValueRe = sync.OnceValue(func() *detectors.Regexp {
	return detectors.MustCompile(
		`(?i)"((?:[A-Za-z0-9_]*(?:password|passwd|pwd|passphrase|secret|api_key|apikey)[A-Za-z0-9_]*)|pass)"\s*:\s*"([^"]{0,500})"`,
	)
})

var placeholders = map[string]struct{}{
	"password":           {},
	"passwd":             {},
	"pass":               {},
	"pwd":                {},
	"secret":             {},
	"changeme":           {},
	"change_me":          {},
	"changeit":           {},
	"example":            {},
	"placeholder":        {},
	"your_password_here": {},
	"admin":              {},
	"root":               {},
	"test":               {},
	"testing":            {},
	"dummy":              {},
	"sample":             {},
	"none":               {},
	"null":               {},
	"n/a":                {},
	"":                   {},
	"x":                  {},
	"xxx":                {},
	"1234":               {},
	"12345":              {},
	"123456":             {},
}

// templateValueRe matches values that are entirely a template marker
// ({secret}, {{ .Token }}, ${API_KEY}, <password>, %(pw)s) rather than a
// literal secret.
var templateValueRe = detectors.MustCompile(`^(?:\$?\{\{?[^{}"]+\}\}?|<[^<>"]+>|%\([^)"]+\)s)$`)

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok || templateValueRe.MatchString(strings.TrimSpace(v))
}

var (
	pascalTypeKeyRe = detectors.MustCompile(`^[A-Z][a-z0-9]+[A-Z][A-Za-z0-9]*$`)
	enumSlugRe      = detectors.MustCompile(`^[a-z]+(?:-[a-z]+)+$`)
)

// isTypeNameEnum reports a Go/TS map literal keyed by a PascalCase type
// name that merely contains a vocabulary word (a detector-name to
// revoke-status table, #886) whose value is a digit-free kebab-case status
// token. Credential-shaped keys in snake/camel case and PascalCase keys with
// non-slug values (a ClientSecret holding a real secret) still report.
// A PascalCase type-name key holding a prose sentence (three or more
// words, a script's per-type rationale table) is documentation too (#943).
func isTypeNameEnum(key, val string) bool {
	if !pascalTypeKeyRe.MatchString(key) {
		return false
	}
	return enumSlugRe.MatchString(val) || len(strings.Fields(val)) >= 3
}

// endsJSONValue reports whether the text after a value's closing quote
// ends a JSON member: a comma, a closing brace or bracket, a JSONC comment,
// or the end of the line. A Go/JS map literal whose value continues as an expression
// (`"secret": "a" + b`, `"secret": "a"[:n]`) is source code, not a JSON
// credential (#919).
func endsJSONValue(rest string) bool {
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return true
	}
	switch rest[0] {
	case ',', '}', ']', '\n', '\r', '/', '#':
		return true
	}
	return false
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JSONConfigSecret }

func (Scanner) Keywords() []string {
	return []string{
		"password", "passwd", "pwd", "pass", "passphrase",
		"secret", "api_key", "apikey",
	}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if bytes.IndexByte(data, '"') < 0 {
		return nil, nil
	}
	str := detectors.BorrowString(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, idx := range jsonKeyValueRe().FindAllStringSubmatchIndex(str, -1) {
		if len(idx) < 6 || !endsJSONValue(str[idx[1]:]) {
			continue
		}
		key, val := str[idx[2]:idx[3]], str[idx[4]:idx[5]]
		if len(val) < 4 {
			continue
		}
		if isPlaceholder(val) || isTypeNameEnum(key, val) {
			continue
		}
		dedupKey := strings.ToLower(key) + "\x00" + val
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.JSONConfigSecret,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"key": strings.Clone(key),
			},
			Severity: detectors.SeverityHigh,
		})
	}

	return detectors.SafeResults(out), nil
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
