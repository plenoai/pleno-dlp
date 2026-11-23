package catalog

import (
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"math/rand"
	"strings"
	"testing"
)

// prefilterInputs generates near-miss and matching inputs per rule.
var prefilterInputs = map[string]func(*rand.Rand) string{
	"betterleaks.zai-api-key": func(rng *rand.Rand) string {
		var b strings.Builder
		for j := 0; j < 1+rng.Intn(4); j++ {
			b.WriteString([]string{" ", "\"", "=", "\n", "x", ".", ""}[rng.Intn(7)])
			for k := 0; k < 28+rng.Intn(8); k++ {
				b.WriteByte("0123456789abcdefABCDEFg"[rng.Intn(23)])
			}
			b.WriteString([]string{".", "..", "-", ""}[rng.Intn(4)])
			for k := 0; k < 14+rng.Intn(4); k++ {
				b.WriteByte("0123456789abcdefXYZxyz"[rng.Intn(22)])
			}
			b.WriteString([]string{"\"", " ", "\n", ";", "'", ""}[rng.Intn(6)])
		}
		return b.String()
	},
	"betterleaks.voyageai-api-key": func(rng *rand.Rand) string {
		var b strings.Builder
		for j := 0; j < 1+rng.Intn(4); j++ {
			b.WriteString([]string{" ", "\"", "=", "\n", "x", "p", ""}[rng.Intn(7)])
			b.WriteString([]string{"pa-", "al-", "pa", "PA-", "pal-"}[rng.Intn(5)])
			for k := 0; k < 40+rng.Intn(6); k++ {
				b.WriteByte("0123456789abcdefXYZ_-."[rng.Intn(22)])
			}
			b.WriteString([]string{"\"", " ", "\n", ";", "'", ""}[rng.Intn(6)])
		}
		return b.String()
	},
	"kingfisher.connection-string.password.odbc-braced": func(rng *rand.Rand) string {
		var b strings.Builder
		b.WriteString([]string{"", " ", ";", "\"", "x"}[rng.Intn(5)])
		b.WriteString([]string{"Server", "host", "Data Source", "DSN", "jdbc:sqlserver://db"}[rng.Intn(5)])
		b.WriteString([]string{"=", " = ", "", ""}[rng.Intn(4)])
		b.WriteString([]string{"db.local;", "x;", "h", "a b;"}[rng.Intn(4)])
		b.WriteString([]string{"", "Database=x;", "uid=sa;"}[rng.Intn(3)])
		b.WriteString([]string{"Password", "pwd", "PWD", "pass"}[rng.Intn(4)])
		b.WriteString([]string{"=", " =\t", "= ", ":", "=x"}[rng.Intn(5)])
		b.WriteString([]string{"{", " {", "\t{", "", "("}[rng.Intn(5)])
		b.WriteString([]string{"s3cr3t!", "a}}b}}cd", "xy", "p@ss w0rd"}[rng.Intn(4)])
		b.WriteString([]string{"}", "};", "}\n", "", "}x"}[rng.Intn(5)])
		return b.String()
	},
}

// TestPrefiltersAreNecessary checks that every prefilter accepts all inputs
// its rule's pattern matches.
func TestPrefiltersAreNecessary(t *testing.T) {
	patterns := map[string]string{}
	for _, r := range append(append([]rule(nil), rules...), extraRules...) {
		patterns[r.ID] = r.Pattern
	}
	rng := rand.New(rand.NewSource(11))
	for id, pre := range prefilters {
		pat, ok := patterns[id]
		if !ok {
			t.Fatalf("prefilter for unknown rule %q", id)
		}
		gen, ok := prefilterInputs[id]
		if !ok {
			t.Fatalf("no input generator for prefiltered rule %q", id)
		}
		re := detectors.MustCompile(pat)
		matched := 0
		for i := 0; i < 20000; i++ {
			data := []byte(gen(rng))
			if re.Match(data) {
				matched++
				if !pre(data) {
					t.Fatalf("%s: prefilter rejected matching input %q", id, data)
				}
			}
		}
		if matched == 0 {
			t.Fatalf("%s: no matching inputs generated", id)
		}
	}
}
