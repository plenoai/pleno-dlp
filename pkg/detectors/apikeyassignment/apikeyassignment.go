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
	"bytes"
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	// The keyword must be at the start of a word (word boundary or line
	// start); the boundary only excludes a preceding letter, so keywords
	// embedded in snake_case names like DO_API_KEY still match.
	assignEqRe = sync.OnceValue(func() *regexp.Regexp {
		return regexp.MustCompile(
			`(?im)(?:^|[^a-zA-Z])[a-zA-Z0-9_]*api[_-]?key[a-zA-Z0-9_]*[ \t]*=[ \t]*(["']?)([^"'\n\r${}<>%\[\]{} #]{4,128})`,
		)
	})
	// This is a necessary-syntax gate for the expensive equality grammar. It
	// deliberately omits the leading boundary and capture limit: the full
	// expression remains authoritative after this conservative prefilter.
	assignEqCandidateRe = sync.OnceValue(func() *regexp.Regexp {
		return regexp.MustCompile(
			`api[_-]?key[a-zA-Z0-9_]*[ \t]*=[ \t]*["']?[^"'\n\r${}<>%\[\]{} #]{4}`,
		)
	})
	assignColonRe = sync.OnceValue(func() *regexp.Regexp {
		return regexp.MustCompile(
			`(?im)(?:^|\s)[a-zA-Z0-9_]*api[_-]?key[a-zA-Z0-9_]*[ \t]*:[ \t]*(["']?)([^"'\n\r${}<>%\[\]{} #]{4,128})`,
		)
	})
)

func hasEqualCandidate(data []byte) bool {
	if bytes.IndexByte(data, '=') < 0 {
		return false
	}
	for _, b := range data {
		if b >= 0x80 {
			// Keep the original case-folding regexp authoritative for Unicode
			// input instead of making a prefilter assumption about its folds.
			return true
		}
	}
	return assignEqCandidateRe().Match(bytes.ToLower(data))
}

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

// goKeywords are reserved words that can follow an api-key-named switch
// case label in source code (#886) but are never a configured key value.
var goKeywords = map[string]struct{}{
	"break": {}, "case": {}, "chan": {}, "const": {}, "continue": {},
	"default": {}, "defer": {}, "else": {}, "fallthrough": {}, "for": {},
	"func": {}, "go": {}, "goto": {}, "if": {}, "import": {},
	"interface": {}, "map": {}, "package": {}, "range": {}, "return": {},
	"select": {}, "struct": {}, "switch": {}, "type": {}, "var": {},
	"nil": {}, "string": {},
}

// looksLikeCode reports whether an unquoted right-hand side is source code
// rather than a config literal: a reserved word, a call, or a digit-free
// identifier carrying a code signal (trailing statement separator,
// camelCase, or a credential word), as in Go struct literals that set an
// api-key field from a variable. Unquoted .env/YAML literals that contain
// digits stay reportable.
func looksLikeCode(v string) bool {
	if strings.ContainsRune(v, '(') {
		return true
	}
	trailing := strings.TrimRight(v, ",;") != v
	v = strings.TrimRight(v, ",;")
	if _, ok := goKeywords[v]; ok {
		return true
	}
	if !identRe.MatchString(v) || strings.ContainsAny(v, "0123456789") {
		return false
	}
	if trailing {
		return true
	}
	for i := 1; i < len(v); i++ {
		if v[i-1] >= 'a' && v[i-1] <= 'z' && v[i] >= 'A' && v[i] <= 'Z' {
			return true
		}
	}
	lower := strings.ToLower(v)
	for _, w := range []string{"key", "secret", "token", "cred"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.APIKeyAssignment }

func (Scanner) Keywords() []string { return []string{"api_key", "api-key", "apikey"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(quote, raw string) {
		val := strings.TrimSpace(strings.TrimRight(raw, `"'`))
		if detectors.HasLeadingEscape(val) || (quote == "" && looksLikeCode(val)) {
			return
		}
		val = strings.TrimRight(val, ",;")
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

	// Avoid running the second full-file regexp when its assignment syntax is
	// absent. Near-match fixtures are dense in `api_key=` references but can be
	// megabytes long; a cheap byte scan is enough to skip the colon grammar.
	res := []*regexp.Regexp{}
	if hasEqualCandidate(data) {
		res = append(res, assignEqRe())
	}
	if bytes.IndexByte(data, ':') >= 0 {
		res = append(res, assignColonRe())
	}
	for _, re := range res {
		for _, m := range re.FindAllSubmatch(data, -1) {
			if len(m) < 3 {
				continue
			}
			add(string(m[1]), string(m[2]))
		}
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
