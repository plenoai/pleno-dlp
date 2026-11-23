package detectors_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/catalog"
)

func TestPrefilterConditions(t *testing.T) {
	cases := []struct {
		expr      string
		reject    []string
		mayAccept []string
	}{
		{`\b([a-f0-9]{32})\b`, []string{"AC twilio 0123456789abcdef", "zzzz"}, []string{"x 0123456789abcdef0123456789abcdef y"}},
		{`\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`, []string{"pat airtable", "patABCDEFGHIJKLMN.abc"}, []string{"patABCDEFGHIJKLMN." + strings.Repeat("a", 64)}},
		{`(?i)(?:sk|pk)_live_[0-9a-z]{24}`, []string{"sk_test_" + strings.Repeat("a", 24)}, []string{"SK_LIVE_" + strings.Repeat("A", 24)}},
		{`\b(key[A-Za-z0-9]{14})\b`, []string{"KEYabcdefghijklmn"}, []string{"keyabcdefghijklmn"}},
		{`(?i)ab|cd`, []string{"xyz"}, []string{"AB", "Cd"}},
		{`a*`, nil, []string{"", "zzz"}},
		{`x|`, nil, []string{"", "zzz"}},
	}
	for _, c := range cases {
		re := regexp.MustCompile(c.expr)
		may, _ := detectors.PrefilterForTest(c.expr)
		for _, s := range c.reject {
			if re.MatchString(s) {
				t.Fatalf("%q: bad case, %q matches", c.expr, s)
			}
			if may([]byte(s)) {
				t.Errorf("%q: prefilter accepted %q", c.expr, s)
			}
		}
		for _, s := range c.mayAccept {
			if !may([]byte(s)) {
				t.Errorf("%q: prefilter rejected %q", c.expr, s)
			}
		}
	}
	// Non-ASCII inputs bypass: U+212A folds to k.
	may, _ := detectors.PrefilterForTest(`(?i)kkkkkkkk`)
	if !may([]byte("Kkkkkkkk")) {
		t.Fatal("non-ASCII input must bypass the prefilter")
	}
}

func TestDetectorRegexpWrapperMatchesStd(t *testing.T) {
	re := detectors.MustCompile(`\b(AC[a-f0-9]{32})\b`)
	std := regexp.MustCompile(re.String())
	for _, s := range []string{"", "AC", "AC" + strings.Repeat("0", 32), "x AC" + strings.Repeat("f", 32) + " y"} {
		if got, want := re.FindAllSubmatchIndex([]byte(s), -1), std.FindAllSubmatchIndex([]byte(s), -1); len(got) != len(want) {
			t.Fatalf("%q: %v vs %v", s, got, want)
		}
		if re.MatchString(s) != std.MatchString(s) || re.FindString(s) != std.FindString(s) {
			t.Fatalf("%q: string methods differ", s)
		}
	}
}

// TestPrefilterNecessaryForAllPatterns generates strings that match each
// detector and format pattern and asserts the prefilter never rejects a
// matching input (#984). Patterns come from every constant MustCompile
// argument under pkg/detectors plus the catalog formats.
func TestPrefilterNecessaryForAllPatterns(t *testing.T) {
	patterns := constantPatterns(t)
	for _, h := range catalog.Hosts() {
		for _, f := range h.Formats() {
			patterns = append(patterns, f.Pattern)
		}
	}
	for _, fs := range catalog.Extensions() {
		for _, f := range fs {
			patterns = append(patterns, f.Pattern)
		}
	}
	if len(patterns) < 500 {
		t.Fatalf("only %d patterns collected", len(patterns))
	}
	rng := rand.New(rand.NewSource(984))
	const pad = "abcdefXYZ0123456789 =:'\"\n\t._-/"
	withPrefilter, matched := 0, 0
	for _, expr := range patterns {
		re, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		may, ok := detectors.PrefilterForTest(expr)
		if !ok {
			continue
		}
		withPrefilter++
		tree, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			continue
		}
		tree = tree.Simplify()
		for i := 0; i < 80; i++ {
			var b strings.Builder
			for j := rng.Intn(4); j > 0; j-- {
				b.WriteByte(pad[rng.Intn(len(pad))])
			}
			if !generate(rng, tree, &b, 0) {
				break
			}
			for j := rng.Intn(4); j > 0; j-- {
				b.WriteByte(pad[rng.Intn(len(pad))])
			}
			s := []byte(b.String())
			if !re.Match(s) {
				continue
			}
			matched++
			if !may(s) {
				t.Fatalf("prefilter rejected a match: %q on %q", expr, s)
			}
		}
	}
	t.Logf("%d patterns, %d with prefilter, %d matching samples", len(patterns), withPrefilter, matched)
	if matched < withPrefilter {
		t.Fatalf("too few matching samples: %d for %d patterns", matched, withPrefilter)
	}
}

// generate appends a random ASCII string from re's language; false means
// the node needs a non-ASCII rune.
func generate(rng *rand.Rand, re *syntax.Regexp, b *strings.Builder, depth int) bool {
	if depth > 40 {
		return false
	}
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return false
			}
			c := byte(r)
			if re.Flags&syntax.FoldCase != 0 && rng.Intn(2) == 0 {
				if 'a' <= c && c <= 'z' {
					c -= 'a' - 'A'
				} else if 'A' <= c && c <= 'Z' {
					c += 'a' - 'A'
				}
			}
			b.WriteByte(c)
		}
		return true
	case syntax.OpCharClass:
		var ascii []byte
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for c := re.Rune[i]; c <= re.Rune[i+1] && c < utf8.RuneSelf; c++ {
				ascii = append(ascii, byte(c))
			}
		}
		if len(ascii) == 0 {
			return false
		}
		b.WriteByte(ascii[rng.Intn(len(ascii))])
		return true
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte("aZ9_ -."[rng.Intn(7)])
		return true
	case syntax.OpCapture:
		return generate(rng, re.Sub[0], b, depth+1)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !generate(rng, s, b, depth+1) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		return generate(rng, re.Sub[rng.Intn(len(re.Sub))], b, depth+1)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := 0, 3
		switch re.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpQuest:
			hi = 1
		case syntax.OpRepeat:
			lo = re.Min
			hi = re.Min + 3
			if re.Max >= 0 && hi > re.Max {
				hi = re.Max
			}
		}
		n := lo + rng.Intn(hi-lo+1)
		for k := 0; k < n; k++ {
			if !generate(rng, re.Sub[0], b, depth+1) {
				return false
			}
		}
		return true
	}
	return true // empty-width assertions and empty match
}

func constantPatterns(t *testing.T) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "MustCompile" {
				return true
			}
			if v, ok := constString(call.Args[0]); ok {
				out = append(out, v)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func constString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return constString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok1 := constString(x.X)
		r, ok2 := constString(x.Y)
		return l + r, ok1 && ok2
	}
	return "", false
}

func TestIndexFoldASCII(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		n := rng.Intn(12)
		b := make([]byte, n)
		for j := range b {
			b[j] = "aAbB-"[rng.Intn(5)]
		}
		lit := []byte{"ab-"[rng.Intn(3)], "ab-"[rng.Intn(3)]}[:1+rng.Intn(2)]
		want := strings.Contains(strings.ToLower(string(b)), string(lit))
		if got := detectors.IndexFoldASCIIForTest(b, lit); got != want {
			t.Fatalf("%q in %q: got %v want %v", lit, b, got, want)
		}
	}
}
