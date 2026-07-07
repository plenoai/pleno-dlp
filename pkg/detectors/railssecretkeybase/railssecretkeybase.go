// Package railssecretkeybase detects Ruby on Rails' `secret_key_base`
// directive, found in `config/secrets.yml` (pre-Rails-5.2 apps) under
// per-environment keys (`development:`, `test:`, `production:`):
//
//	development:
//	  secret_key_base: e0ec946fcefea5ce0d4d924f3c8db11dffeb7d1...
//
// `secret_key_base` signs and encrypts Rails' session cookies; leaking
// it lets an attacker forge arbitrary signed/encrypted session state.
// Rails generates it via `rake secret` / `bin/rails secret` — 128 hex
// characters (SecureRandom.hex(64)) — so the value length floor here is
// set well above hardcodedpassword's generic 4-character floor to keep
// this detector specific to that shape rather than any short YAML
// scalar that happens to follow the same key name.
//
// The `production:` block conventionally reads from the environment
// instead of a literal (`secret_key_base: <%= ENV["SECRET_KEY_BASE"]
// %>`); the ERB/templating-marker check below excludes that form since
// it is not a literal secret in this file.
//
// Verify is deliberately not implemented (class b): the value only has
// meaning to the specific Rails application instance that generated it
// — there is no provider endpoint to probe.
package railssecretkeybase

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// lineRe matches a `secret_key_base:` YAML line and captures the
// (possibly quoted) value token.
var lineRe = regexp.MustCompile(
	`(?im)^[ \t]*secret_key_base:[ \t]+(\S+)[ \t]*$`,
)

var placeholders = map[string]struct{}{
	"changeme":    {},
	"change_me":   {},
	"example":     {},
	"placeholder": {},
	"secret":      {},
	"test":        {},
	"dummy":       {},
	"sample":      {},
	"none":        {},
	"null":        {},
	"":            {},
}

func hasTemplatingMarker(v string) bool {
	for _, marker := range []string{"<%", "${", "{{", "env["} {
		if strings.Contains(strings.ToLower(v), marker) {
			return true
		}
	}
	return false
}

func isPlaceholder(v string) bool {
	lower := strings.ToLower(strings.Trim(v, `"'`))
	if _, ok := placeholders[lower]; ok {
		return true
	}
	return hasTemplatingMarker(v)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RailsSecretKeyBase }

func (Scanner) Keywords() []string { return []string{"secret_key_base"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range lineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 2 {
			continue
		}
		raw := m[1]
		val := strings.Trim(raw, `"'`)
		if isPlaceholder(raw) {
			continue
		}
		// Rails-generated values are 128 hex chars; a much shorter
		// scalar under the same key is unlikely to be a real Rails
		// secret_key_base and more likely a stub/test fixture.
		if len(val) < 32 {
			continue
		}
		if _, dup := seen[val]; dup {
			continue
		}
		seen[val] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.RailsSecretKeyBase,
			Raw:          []byte(val),
			Redacted:     val[:4] + "...",
			Severity:     detectors.SeverityHigh,
		})
	}

	return out, nil
}

func init() {
	detectors.Register(Scanner{})
}
