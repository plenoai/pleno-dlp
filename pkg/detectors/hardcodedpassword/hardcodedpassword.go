// Package hardcodedpassword detects low-entropy hardcoded passwords in
// IaC and config files. Unlike entropy-gated detectors, it deliberately
// surfaces short, guessable passwords in Terraform defaults, Kubernetes
// env vars, docker-compose blocks, and INI/YAML assignments.
//
// Because these passwords authenticate against customer-controlled
// infrastructure whose endpoints are not present in the matched chunk,
// Verify is deliberately not implemented (class b).
package hardcodedpassword

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// We intentionally do NOT gate on Shannon entropy — low-entropy hardcoded
// passwords are exactly the target.
var (
	// The keyword must be at the start of a word (word boundary or line
	// start); the boundary only excludes a preceding letter, so keywords
	// embedded in snake_case names like DB_PASSWORD still match.
	assignEqRe = sync.OnceValue(func() *detectors.Regexp {
		return detectors.MustCompile(
			`(?im)(?:^|[^a-zA-Z])(?:password|passwd|pwd)(?:[^a-z0-9_][^\n=]*)?` +
				`\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
		)
	})

	// The mapping separator and value must share the key's line (#886): a
	// Go `case XPassword:` label followed by a statement is not YAML.
	yamlValueRe = sync.OnceValue(func() *detectors.Regexp {
		return detectors.MustCompile(
			`(?im)(?:^|\s)(?:[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*)[ \t]*:[ \t]*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
		)
	})

	// The keyword lives in the variable name and the literal `default =`
	// value on a different line, so assignEqRe cannot see them together;
	// this pattern captures the block body separately and re-scans it for
	// the default line.
	tfVariableRe = sync.OnceValue(func() *detectors.Regexp {
		return detectors.MustCompile(
			`(?i)variable\s*"[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*"\s*\{([^}]*)\}`,
		)
	})
	tfDefaultRe = sync.OnceValue(func() *detectors.Regexp {
		return detectors.MustCompile(
			`(?im)^\s*default\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
		)
	})
)

// Match the complete assignment suffix in one RE2 pass over lower-cased bytes.
// The previous implementation called an anchored regexp once per keyword
// occurrence; repeated non-assignments could rescan the same tail quadratically.
var assignmentHeadRe = sync.OnceValue(func() *detectors.Regexp {
	return detectors.MustCompile(
		`(?:password|passwd|pwd)(?:(?:[^a-z0-9_][^\n=]*)?\s*=|[a-z0-9_]*\s*:)`,
	)
})

func hasAssignmentHead(data []byte) bool {
	// Every accepted grammar branch requires an ASCII assignment or mapping
	// separator. This cheap reject keeps repeated prose keywords out of the
	// RE2 scan; it also precedes the Unicode case-fold fallback below.
	if !bytes.ContainsAny(data, "=:") {
		return false
	}
	for _, b := range data {
		if b >= 0x80 {
			// RE2 also folds Unicode letters such as long s; let it decide.
			return true
		}
	}
	lower := bytes.ToLower(data)
	return bytes.Contains(lower, []byte("variable")) ||
		(hasAssignmentCandidate(lower) && assignmentHeadRe().Match(lower))
}

// Each separator is visited once. After removing RE2 whitespace, an assignment
// needs a keyword on the remaining last line, or immediately before its newline
// (the optional non-word byte in assignmentHeadRe can consume that newline).
func hasAssignmentCandidate(lower []byte) bool {
	for len(lower) > 0 {
		end := bytes.IndexAny(lower, "=:")
		if end < 0 {
			return false
		}
		head := bytes.TrimRight(lower[:end], " \t\n\f\r")
		line := bytes.LastIndexByte(head, '\n') + 1
		for _, keyword := range []string{"password", "passwd", "pwd"} {
			if bytes.Contains(head[line:], []byte(keyword)) ||
				(line > 0 && bytes.HasSuffix(head[:line-1], []byte(keyword))) {
				return true
			}
		}
		lower = lower[end+1:]
	}
	return false
}

var placeholders = func() map[string]struct{} {
	words := []string{
		"example", "changeme", "change_me", "changeit", "change-me",
		"test", "testing", "default", "dummy", "sample", "placeholder",
		"password", "passwd", "secret", "mysecret", "mysecretkey",
		"yourpassword", "your_password", "your-password",
		"admin", "admin123", "administrator", "root", "root123",
		"pass", "1234", "12345", "123456", "1234567", "12345678", "123456789",
		"null", "none", "n/a", "na", "true", "false",
		"todo", "fixme", "replace", "insert", "your", "xxx", "yyy", "zzz",
		"abc", "abcdef", "foo", "bar", "baz", "qwerty", "letmein",
		"welcome", "iloveyou", "sunshine", "princess", "monkey",
		"password123", "passwd123", "p@ssword", "p@ssw0rd",
		"enter_password_here", "insert_password_here", "replace_me",
		"type_your_password", "put_password_here",
		"strong_password", "secure_password",
		"notset", "not_set", "unset", "undefined", "empty",
		"required", "missing", "must_be_set", "set_this",
		// Credential-descriptor labels: doc/example code that names the
		// *kind* of secret to supply rather than supplying one, e.g.
		// `Password: "github_access_token"` in a "how to auth" snippet.
		// Same rationale as the your_password-style entries above.
		"token", "access_token", "api_token", "auth_token", "your_token",
		"github_access_token", "personal_access_token", "your_access_token",
		"username", "user", "your_username",
	}
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}()

func hasTemplatingMarker(v string) bool {
	for _, marker := range []string{"${", "{{", "<%", "%{", "<", ">"} {
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

// trailingSeparators are statement/grouping punctuation that can trail an
// unquoted capture when the keyword appears in general-purpose source
// rather than IaC/config syntax — e.g. a Go struct-literal field
// `Password: password,` or a multi-value assignment
// `password, ok = f()`. A real config value never legitimately ends in
// these, so trimming them is lossless for genuine hits and lets the
// placeholder/code-reference checks below see the bare word underneath.
const trailingSeparators = ",;"

func normalizeValue(raw string) string {
	v := strings.TrimSpace(raw)
	return strings.TrimRight(v, trailingSeparators)
}

// looksLikeCodeReference reports whether v is a bare source-code
// expression rather than a literal value: a function/method call
// (contains "(") or a dotted package-style selector such as os.Args or
// strings.Cut, where every dot-separated segment is pure letters/
// underscore.
//
// assignEqRe and yamlValueRe key off `keyword = value` / `keyword :
// value`, a shape Go also uses for `password := os.Args[3]` and
// struct-literal fields like `Password: token,`. Those right-hand sides
// are variable/expression references, never hardcoded literals. A
// letters-only dotted segment (no digits, no other punctuation) is
// definitionally a Go/Python/JS package or field selector — real
// passwords overwhelmingly contain digits or symbols (see
// looksLikeIdentifier in pkg/detectors/generic for the same
// no-digits-means-identifier reasoning).
func looksLikeCodeReference(v string) bool {
	if strings.ContainsRune(v, '(') {
		return true
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			isLetterOrUnderscore := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
			if !isLetterOrUnderscore {
				return false
			}
		}
	}
	return true
}

// identRe matches a bare source-code identifier.
var identRe = detectors.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// looksLikeIdentifierRef reports whether an unquoted right-hand side is a
// variable reference rather than a literal (#863): `target.Password =
// appPassword`, `"app_password": appPassword,`. Unquoted literals in
// .env/INI files are lexically identifiers too (`password=hunter2`), so pleno-dlp:allow
// only digit-free identifiers that carry a code signal are dropped: a
// camelCase transition, a credential word in the name, or a trailing
// statement separator.
func looksLikeIdentifierRef(raw string) bool {
	v := strings.TrimSpace(raw)
	trailing := strings.TrimRight(v, trailingSeparators) != v
	v = strings.TrimRight(v, trailingSeparators)
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
	for _, w := range []string{"password", "passwd", "pwd", "pass", "secret", "token", "cred"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// multiAssignTarget resolves a tuple assignment such as
// `target.Username, target.Password = "oauth2", token` (#863). It reports
// multi=false when the line holding valueStart is not a tuple assignment.
// Otherwise it returns the right-hand literal positionally matched to the
// password-named left-hand element, or "" when that element is not a
// quoted literal (identifier, call, or missing).
func multiAssignTarget(str string, valueStart int) (string, bool) {
	lineStart := strings.LastIndexByte(str[:valueStart], '\n') + 1
	lineEnd := strings.IndexByte(str[valueStart:], '\n')
	if lineEnd < 0 {
		lineEnd = len(str)
	} else {
		lineEnd += valueStart
	}
	line := str[lineStart:lineEnd]
	eq := strings.IndexByte(line, '=')
	if eq < 0 || lineStart+eq >= valueStart {
		return "", false
	}
	lhs := strings.TrimSuffix(strings.TrimSpace(line[:eq]), ":")
	if !strings.Contains(lhs, ",") || strings.ContainsAny(lhs, "\"'") {
		return "", false
	}
	names := strings.Split(lhs, ",")
	target := -1
	for i, n := range names {
		ln := strings.ToLower(n)
		if strings.Contains(ln, "password") || strings.Contains(ln, "passwd") || strings.Contains(ln, "pwd") {
			target = i
		}
	}
	if target < 0 {
		return "", true
	}
	values := splitTopLevelCommas(line[eq+1:])
	if target >= len(values) {
		return "", true
	}
	v := strings.TrimSpace(values[target])
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1], true
	}
	return "", true
}

// splitTopLevelCommas splits s on commas outside quotes and brackets.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// opensCompositeLiteral reports whether an unquoted capture ending at end
// is immediately followed by `{` or `(`: the right-hand side is a type
// or call (`seen[password] = struct{}{}`), not a literal (#943).
func opensCompositeLiteral(str string, end int) bool {
	return end < len(str) && (str[end] == '{' || str[end] == '(')
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.HardcodedPassword }

func (Scanner) Keywords() []string {
	return []string{"password", "passwd", "pwd"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !hasAssignmentHead(data) {
		return nil, nil
	}
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(raw string) {
		val := normalizeValue(raw)
		if len(val) < 4 {
			return
		}
		if isPlaceholder(val) || looksLikeCodeReference(val) || detectors.HasLeadingEscape(val) {
			return
		}
		if _, dup := seen[val]; dup {
			return
		}
		seen[val] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.HardcodedPassword,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"finding_class": "credential",
			},
			Severity: detectors.SeverityHigh,
		})
	}

	for _, re := range []*detectors.Regexp{assignEqRe(), yamlValueRe()} {
		for _, m := range re.FindAllStringSubmatchIndex(str, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			if v, multi := multiAssignTarget(str, m[2]); multi {
				if v != "" {
					add(v)
				}
				continue
			}
			raw := str[m[2]:m[3]]
			quoted := m[2] > 0 && (str[m[2]-1] == '"' || str[m[2]-1] == '\'')
			if !quoted && (looksLikeIdentifierRef(raw) || opensCompositeLiteral(str, m[3])) {
				continue
			}
			add(raw)
		}
	}

	for _, block := range tfVariableRe().FindAllStringSubmatch(str, -1) {
		if len(block) < 2 {
			continue
		}
		if m := tfDefaultRe().FindStringSubmatch(block[1]); len(m) >= 2 {
			add(m[1])
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
