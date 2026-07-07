// Package hardcodedpassword detects low-entropy hardcoded passwords in
// IaC and config files. Unlike entropy-gated detectors, this detector is
// explicitly designed to surface short, guessable passwords that appear in
// Terraform variable defaults, Kubernetes env-var values, docker-compose
// environment blocks, and INI/YAML key = value assignments.
//
// Because these passwords are valid against customer-controlled infrastructure
// (database hosts, auth services) whose endpoints are not present in the
// matched chunk, Verify is deliberately not implemented (class b).
// Hardened: placeholder denylist, templating-marker gate, minimum-length gate.
package hardcodedpassword

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Assignment patterns. We match `<password-keyword> <sep> <value>` where:
//   - The keyword is password/passwd/pwd (case-insensitive) possibly as part of
//     a larger name like DB_PASSWORD or app.password.
//   - The separator is `=` (shell/tf/ini) or `:` followed by a space (YAML).
//   - The value may be quoted with " or ' or unquoted.
//
// We intentionally do NOT gate on Shannon entropy — low-entropy hardcoded
// passwords are exactly the target (e.g. "Aa1234321Bb", "root123", "P@ssw0rd").
var (
	// Shell / INI / Terraform: DB_PASSWORD=value  or  password = "value"
	// The keyword must be at the start of a word (word boundary or line
	// start); the boundary only excludes a preceding letter, so keywords
	// embedded in snake_case names like DB_PASSWORD still match.
	assignEqRe = regexp.MustCompile(
		`(?im)(?:^|[^a-zA-Z])(?:password|passwd|pwd)(?:[^a-z0-9_][^\n=]*)?` +
			`\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)

	// YAML block: "  - name: DB_PASSWORD\n    value: foo" or "DB_PASSWORD: foo"
	yamlValueRe = regexp.MustCompile(
		`(?im)(?:^|\s)(?:[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*)\s*:\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)

	// Terraform variable block whose *name* contains the keyword, with the
	// literal default on its own line inside the block:
	//   variable "db_password" {
	//     default = "Aa1234321Bb"
	//   }
	// The keyword and the `default =` assignment are not on the same line,
	// so assignEqRe cannot see them together — this pattern captures the
	// block body separately and re-scans it for the default line.
	tfVariableRe = regexp.MustCompile(
		`(?i)variable\s*"[a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*"\s*\{([^}]*)\}`,
	)
	tfDefaultRe = regexp.MustCompile(
		`(?im)^\s*default\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
	)
)

// placeholders lists values that are clearly documentation fillers,
// template markers, or common weak passwords that should be excluded.
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
	}
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}()

// hasTemplatingMarker returns true when the value contains a template
// variable marker — these are never literal credentials.
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
		val := strings.TrimSpace(raw)
		if len(val) < 4 {
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

	// Terraform variable blocks: the keyword lives in the variable name,
	// the literal value in a `default = "..."` line elsewhere in the block.
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
