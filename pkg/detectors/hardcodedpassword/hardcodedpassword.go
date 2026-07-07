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
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// We intentionally do NOT gate on Shannon entropy — low-entropy hardcoded
// passwords are exactly the target.
var (
	// The keyword must be at the start of a word (word boundary or line
	// start); the boundary only excludes a preceding letter, so keywords
	// embedded in snake_case names like DB_PASSWORD still match.
	assignEqRe = regexp.MustCompile(
		`(?im)(?:^|[^a-zA-Z])(?:password|passwd|pwd)(?:[^a-z0-9_][^\n=]*)?` +
			`\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)

	yamlValueRe = regexp.MustCompile(
		`(?im)(?:^|\s)(?:[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*)\s*:\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)

	// The keyword lives in the variable name and the literal `default =`
	// value on a different line, so assignEqRe cannot see them together;
	// this pattern captures the block body separately and re-scans it for
	// the default line.
	tfVariableRe = regexp.MustCompile(
		`(?i)variable\s*"[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*"\s*\{([^}]*)\}`,
	)
	tfDefaultRe = regexp.MustCompile(
		`(?im)^\s*default\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)
)

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

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.HardcodedPassword }

func (Scanner) Keywords() []string {
	return []string{"password", "passwd", "pwd"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	add := func(raw string) {
		val := normalizeValue(raw)
		if len(val) < 4 {
			return
		}
		if isPlaceholder(val) || looksLikeCodeReference(val) {
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

	for _, re := range []*regexp.Regexp{assignEqRe, yamlValueRe} {
		for _, m := range re.FindAllStringSubmatch(str, -1) {
			if len(m) < 2 {
				continue
			}
			add(m[1])
		}
	}

	for _, block := range tfVariableRe.FindAllStringSubmatch(str, -1) {
		if len(block) < 2 {
			continue
		}
		if m := tfDefaultRe.FindStringSubmatch(block[1]); len(m) >= 2 {
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
