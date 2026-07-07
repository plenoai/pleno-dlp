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
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// jsonKeyValueRe matches a JSON string key/value pair whose key either
// equals "pass" exactly or contains one of the longer credential
// vocabulary words as a substring (case-insensitive), covering
// camelCase (userPassword), snake_case (db_password), and
// SCREAMING_SNAKE (HEROKU_API_KEY) key styles alike.
var jsonKeyValueRe = regexp.MustCompile(
	`(?i)"((?:[A-Za-z0-9_]*(?:password|passwd|pwd|passphrase|secret|api_key|apikey)[A-Za-z0-9_]*)|pass)"\s*:\s*"([^"]{0,500})"`,
)

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

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
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
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range jsonKeyValueRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		key, val := m[1], m[2]
		if len(val) < 4 {
			continue
		}
		if isPlaceholder(val) {
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
				"key": key,
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
