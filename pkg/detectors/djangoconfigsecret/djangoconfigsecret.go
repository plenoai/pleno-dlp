// Package djangoconfigsecret detects two Python assignment shapes found
// in Django's settings.py:
//
//   - the module-level `SECRET_KEY = '...'` constant Django's own
//     `startproject` scaffolding generates (django.core.management.utils
//     .get_random_secret_key()'s alphabet includes `!@#$%^&*(-_=+)`, so
//     the captured value is intentionally not restricted to a "safe"
//     character class the way some other assignment detectors are).
//   - the `'PASSWORD': '...'` quoted-dict-key entry inside a DATABASES
//     block, e.g.:
//
//     DATABASES = {
//     'default': {
//     'ENGINE': 'django.db.backends.postgresql',
//     'PASSWORD': 'hunter2',
//     }
//     }
//
// Neither shape is covered by an existing detector. hardcodedpassword
// implements the identical `key = value` / `key: value` matching, but
// its regexes anchor the keyword on a preceding word boundary or
// whitespace (`(?:^|[^a-zA-Z])` / `(?:^|\s)`); a Python dict key is
// always preceded by the opening quote (`'PASSWORD'`), which is neither,
// so hardcodedpassword's password/passwd/pwd keyword set never reaches
// this shape even where the two overlap semantically. JSONConfigSecret
// is JSON, not Python, and does not parse `.py` assignment syntax at
// all.
//
// Verify is deliberately not implemented (class b): SECRET_KEY signs
// Django's session/CSRF cookies and has no provider to probe, and the
// DATABASES password authenticates against a host that (for the
// DATABASES shape captured here) is not co-located with the matched
// value in the chunk.
package djangoconfigsecret

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// secretKeyRe matches Django's `SECRET_KEY = '...'` module constant.
// The value character class only excludes the enclosing quote character
// and newlines — deliberately permissive, since Django's default
// generated secret key legitimately contains `$`, `[`, `]`, `(`, `)`,
// `^`, `+`, and `=`.
// Go's RE2 has no backreferences, so the opening/closing quote is not
// required to match (a mismatched-quote value is not valid Python and
// essentially never appears in real files).
var secretKeyRe = regexp.MustCompile(
	`(?m)^[ \t]*SECRET_KEY[ \t]*=[ \t]*['"]([^'"\r\n]{8,256})['"][ \t]*$`,
)

// dbPasswordRe matches a quoted-key Python dict entry named PASSWORD
// (case-insensitive to also catch the less common lowercase
// convention), the shape Django's DATABASES block uses.
var dbPasswordRe = regexp.MustCompile(
	`(?im)['"]PASSWORD['"][ \t]*:[ \t]*['"]([^'"\r\n]{1,256})['"]`,
)

var placeholders = map[string]struct{}{
	"password":              {},
	"changeme":              {},
	"change_me":             {},
	"changeit":              {},
	"example":               {},
	"placeholder":           {},
	"secret":                {},
	"test":                  {},
	"testing":               {},
	"dummy":                 {},
	"sample":                {},
	"none":                  {},
	"null":                  {},
	"n/a":                   {},
	"x":                     {},
	"xxx":                   {},
	"":                      {},
	"your-secret-key-here":  {},
	"your_secret_key_here":  {},
	"changethiskey":         {},
	"insecure-secret-key":   {},
	"replace-with-your-key": {},
}

func hasTemplatingMarker(v string) bool {
	for _, marker := range []string{"${", "{{", "<%", "%(", "os.environ", "os.getenv"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func isPlaceholder(v string) bool {
	lower := strings.ToLower(strings.TrimSpace(v))
	if _, ok := placeholders[lower]; ok {
		return true
	}
	return hasTemplatingMarker(v)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DjangoConfigSecret }

func (Scanner) Keywords() []string { return []string{"SECRET_KEY", "PASSWORD"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(val, kind string) {
		if len(val) < 4 {
			return
		}
		if isPlaceholder(val) {
			return
		}
		key := kind + ":" + val
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.DjangoConfigSecret,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"kind": kind,
			},
			Severity: detectors.SeverityHigh,
		})
	}

	for _, m := range secretKeyRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 2 {
			continue
		}
		add(m[1], "secret_key")
	}
	for _, m := range dbPasswordRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 2 {
			continue
		}
		add(m[1], "database_password")
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
