//go:build detector_unit

package hardcodedpassword

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

var legacyAssignmentHeadRe = regexp.MustCompile(
	`(?:password|passwd|pwd)(?:(?:[^a-z0-9_][^\n=]*)?\s*=|[a-z0-9_]*\s*:)`,
)

func legacyHasAssignmentHeadASCII(s string) bool {
	if !strings.ContainsAny(s, "=:") {
		return false
	}
	lower := strings.ToLower(s)
	return strings.Contains(lower, "variable") || legacyAssignmentHeadRe.MatchString(lower)
}

func TestFromData_TerraformDefault(t *testing.T) {
	data := []byte(`variable "db_password" {
  default = "Aa1234321Bb"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Aa1234321Bb" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_DockerComposeEnv(t *testing.T) {
	data := []byte("DB_PASSWORD=P@ssw0rdXz99\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "P@ssw0rdXz99" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"template var", `password = ${DB_PASSWORD}`},
		{"placeholder changeme", `password = "changeme"`},
		{"placeholder example", `db_password = example`},
		{"too short", `password = abc`},
		{"null", `password = null`},
		{"brace template", `password = {{.Password}}`},
		// go-git v5.19.0 shapes (issue #294): the keyword regexes key off
		// `password = value` / `password: value`, which Go source also
		// uses for statements that are never hardcoded literals.
		{"value equals variable name (struct field)", `Password: password,`},
		{"value equals variable name (short form)", `Password: pass,`},
		{"bare dotted identifier", `password := os.Args[3]`},
		{"multi-assign from function call", `username, password, ok = strings.Cut(cs, ":")`},
		{"credential-descriptor label value", `Password: "github_access_token",`},
		{"credential-descriptor label value bare", `Password: token,`},
		{"swapped-field username placeholder", `password = "username"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}

// TestFromData_RealSecretsStillFire guards against the placeholder and
// code-reference suppressions added for issue #294 over-broadening and
// swallowing genuinely secret-looking literals.
func TestFromData_RealSecretsStillFire(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"quoted literal with digits and symbols", `Password: "Sup3r#ecret!99",`, "Sup3r#ecret!99"},
		{"dotted-looking but has digits", `password = v2.Secret9x`, "v2.Secret9x"},
		{"terraform default", `variable "db_password" {
  default = "Aa1234321Bb"
}`, "Aa1234321Bb"},
		{"docker-compose env", "DB_PASSWORD=P@ssw0rdXz99\n", "P@ssw0rdXz99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 1 {
				t.Fatalf("expected 1 finding, got %d for %q", len(res), tc.data)
			}
			if string(res[0].Raw) != tc.want {
				t.Fatalf("got %q, want %q", res[0].Raw, tc.want)
			}
		})
	}
}

func TestLooksLikeCodeReference(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"os.Args", true},
		{"strings.Cut(cs", true},
		{"fmt.Println", true},
		{"foo(", true},
		{"Aa1234321Bb", false},
		{"P@ssw0rdXz99", false},
		{"v2.Secret9x", false}, // has digits — not a pure identifier selector
		{"my.pass.word", true},
		{"", false},
		{"a.", false},
	}
	for _, c := range cases {
		if got := looksLikeCodeReference(c.s); got != c.want {
			t.Errorf("looksLikeCodeReference(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestAssignmentHeadPreservesGrammar(t *testing.T) {
	for _, input := range []string{
		"db_password = 'R8!actualValue'",
		"Paſſword = 'R8!actualValue'",
		"password\n\n = 'R8!actualValue'",
		"password:\nname = 'R8!actualValue'",
		"db_password_suffix\n : 'R8!actualValue'",
		"variable \"db_password\" {\n default = \"R8!actualValue\"\n}",
	} {
		if !assignEqRe().MatchString(input) && !yamlValueRe().MatchString(input) && !tfVariableRe().MatchString(input) {
			t.Fatalf("fixture does not match original grammar: %q", input)
		}
		if !hasAssignmentHead([]byte(input)) {
			t.Fatalf("prefilter rejected original grammar: %q", input)
		}
	}
}

func TestHasAssignmentHeadASCIIEquivalent(t *testing.T) {
	inputs := []string{
		"password = 'R8!actualValue'",
		"PASSWORD=R8!actualValue",
		"db_password: 'R8!actualValue'",
		"passwd\n\n = 'R8!actualValue'",
		"pwd_suffix\n : 'R8!actualValue'",
		"variable \"db_password\" {\n default = \"R8!actualValue\"\n}",
		"variable: a prose label",
		"password words with no assignment",
		"prefix password? and unrelated: punctuation",
	}
	for _, input := range inputs {
		if !isASCII(input) {
			t.Fatalf("differential fixture is not ASCII: %q", input)
		}
		want := legacyHasAssignmentHeadASCII(input)
		if got := hasAssignmentHead([]byte(input)); got != want {
			t.Errorf("hasAssignmentHead(%q) = %v, legacy = %v", input, got, want)
		}
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func TestHasAssignmentHeadRequiresSeparator(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"keyword storm prose", strings.Repeat("secret key token password access api auth ", 32), false},
		{"terraform variable default", "variable \"db_password\" {\n default = \"R8!actualValue\"\n}", true},
		{"colon mapping", "Password: \"R8!actualValue\"", true},
		{"equals assignment", "DB_PASSWORD=R8!actualValue", true},
		{"unicode keyword without separator", "Paſſword R8!actualValue", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAssignmentHead([]byte(tc.data)); got != tc.want {
				t.Fatalf("hasAssignmentHead(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}
