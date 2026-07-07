// Package apikeyassignment detects low-entropy `api_key`/`api-key`/
// `apikey` assignments in ini/YAML-shaped config files —
// `key: value` or `key = value`, unquoted key, optionally trailed by a
// `#` comment — the same family of shapes hardcodedpassword already
// covers for `password`/`passwd`/`pwd`, but for a distinct keyword
// hardcodedpassword deliberately does not key on (an unqualified
// "key" substring match would be far too broad for that detector's
// generic assignment scan). The motivating fixture is DigitalOcean's
// `.tugboat` deploy config (`api_key: <value> # Risk.`), but the same
// `key: value` grammar shows up in countless other IaC/ops YAML/ini
// files that provision a bare API key rather than a password.
//
// We intentionally do NOT gate on Shannon entropy, matching
// hardcodedpassword's rationale: low-entropy hardcoded keys are exactly
// the target here too.
//
// Verify is deliberately not implemented (class b): the value
// authenticates against whatever service the surrounding config
// targets, which is data-controlled and not derivable from the matched
// chunk alone.
package apikeyassignment

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	// The keyword must be at the start of a word (word boundary or line
	// start); the boundary only excludes a preceding letter, so keywords
	// embedded in snake_case names like DO_API_KEY still match.
	assignEqRe = regexp.MustCompile(
		`(?im)(?:^|[^a-zA-Z])[a-zA-Z0-9_]*api[_-]?key[a-zA-Z0-9_]*\s*=\s*["']?([^"'\n\r${}<>%\[\]{} #]{4,128})`,
	)
	assignColonRe = regexp.MustCompile(
		`(?im)(?:^|\s)[a-zA-Z0-9_]*api[_-]?key[a-zA-Z0-9_]*\s*:\s*["']?([^"'\n\r${}<>%\[\]{} #]{4,128})`,
	)
)

var placeholders = map[string]struct{}{
	"changeme":          {},
	"change_me":         {},
	"changeit":          {},
	"example":           {},
	"test":              {},
	"testing":           {},
	"dummy":             {},
	"sample":            {},
	"placeholder":       {},
	"your_api_key":      {},
	"your_api_key_here": {},
	"insert_key_here":   {},
	"todo":              {},
	"fixme":             {},
	"replace_me":        {},
	"null":              {},
	"none":              {},
	"n/a":               {},
	"na":                {},
	"true":              {},
	"false":             {},
	"":                  {},
	"x":                 {},
	"xxx":               {},
	"1234":              {},
	"12345":             {},
	"123456":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

func hasTemplatingMarker(v string) bool {
	for _, marker := range []string{"${", "{{", "<%", "%{", "<", ">"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.APIKeyAssignment }

func (Scanner) Keywords() []string { return []string{"api_key", "api-key", "apikey"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(raw string) {
		val := strings.TrimSpace(strings.TrimRight(raw, `"'`))
		if len(val) < 4 {
			return
		}
		if hasTemplatingMarker(val) {
			return
		}
		if isPlaceholder(val) {
			return
		}
		if _, dup := seen[val]; dup {
			return
		}
		seen[val] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.APIKeyAssignment,
			Raw:          []byte(val),
			Redacted:     redact(val),
			Severity:     detectors.SeverityHigh,
		})
	}

	for _, re := range []*regexp.Regexp{assignEqRe, assignColonRe} {
		for _, m := range re.FindAllStringSubmatch(str, -1) {
			if len(m) < 2 {
				continue
			}
			add(m[1])
		}
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
