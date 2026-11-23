package detectors_test

import (
	"math/rand"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/catalog"
)

// narrowNoise mixes ASCII text with the bytes that stress span edges:
// line breaks, quotes, multi-byte runes, the two non-ASCII runes that fold
// to ASCII letters (U+017F, U+212A), and invalid UTF-8.
var narrowNoise = []string{
	"the", "password", "secret", "key", "token", "=", ":", " ", " ", "\n", "\t",
	"\"", "'", "_", "-", ".", "/", "@", "{", "}", "(", ")", "$", "é", "日本",
	"ſ", "K", "\xff", "\xe2\x82", "\x80", "0123456789abcdef",
	"ABCDEFGHIJKLMNOP", "https://", "-----BEGIN ", "AKIA", "eyJ", "ghp_",
}

func narrowDoc(rng *rand.Rand, tree *syntax.Regexp, ascii bool) []byte {
	var b strings.Builder
	n := 200 + rng.Intn(3000)
	for b.Len() < n {
		if rng.Intn(40) == 0 {
			var m strings.Builder
			if generate(rng, tree, &m, 0) {
				b.WriteString(m.String())
				continue
			}
		}
		w := narrowNoise[rng.Intn(len(narrowNoise))]
		if ascii {
			for i := 0; i < len(w); i++ {
				if w[i] >= 0x80 {
					w = "x"
					break
				}
			}
		}
		b.WriteString(w)
	}
	return []byte(b.String())
}

// TestAnchorNarrowingMatchesStd checks every detector and format pattern:
// the narrowed wrapper must return exactly what the standard library
// returns over the whole input, for every method family (#1034).
func TestAnchorNarrowingMatchesStd(t *testing.T) {
	patterns := constantPatterns(t)
	formats := 0
	for _, h := range catalog.Hosts() {
		for _, f := range h.Formats() {
			patterns = append(patterns, f.Pattern)
			formats++
		}
	}
	for _, fs := range catalog.Extensions() {
		for _, f := range fs {
			patterns = append(patterns, f.Pattern)
		}
	}
	rng := rand.New(rand.NewSource(1034))
	docs := 12
	if testing.Short() {
		docs = 3
	}
	anchored, matched := 0, 0
	for _, expr := range patterns {
		std, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		if !detectors.AnchoredForTest(expr) {
			continue
		}
		anchored++
		re := detectors.MustCompile(expr)
		tree, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		tree = tree.Simplify()
		f := &detectors.Format{Pattern: expr}
		for i := 0; i < docs; i++ {
			doc := narrowDoc(rng, tree, i%2 == 0)
			want := std.FindAllSubmatchIndex(doc, -1)
			matched += len(want)
			checkSame(t, expr, doc, "FindAllSubmatchIndex", re.FindAllSubmatchIndex(doc, -1), want)
			checkSame(t, expr, doc, "FindAllSubmatchIndex(2)", re.FindAllSubmatchIndex(doc, 2), std.FindAllSubmatchIndex(doc, 2))
			checkSame(t, expr, doc, "FindAllIndex", re.FindAllIndex(doc, -1), std.FindAllIndex(doc, -1))
			checkSame(t, expr, doc, "FindAll", re.FindAll(doc, -1), std.FindAll(doc, -1))
			checkSame(t, expr, doc, "FindAllSubmatch", re.FindAllSubmatch(doc, -1), std.FindAllSubmatch(doc, -1))
			checkSame(t, expr, doc, "FindSubmatchIndex", re.FindSubmatchIndex(doc), std.FindSubmatchIndex(doc))
			checkSame(t, expr, doc, "FindIndex", re.FindIndex(doc), std.FindIndex(doc))
			checkSame(t, expr, doc, "Match", re.Match(doc), std.Match(doc))
			s := string(doc)
			checkSame(t, expr, doc, "FindAllStringSubmatch", re.FindAllStringSubmatch(s, -1), std.FindAllStringSubmatch(s, -1))
			checkSame(t, expr, doc, "FindAllString", re.FindAllString(s, 3), std.FindAllString(s, 3))
			checkSame(t, expr, doc, "FindStringSubmatch", re.FindStringSubmatch(s), std.FindStringSubmatch(s))
			checkSame(t, expr, doc, "FindString", re.FindString(s), std.FindString(s))
			checkSame(t, expr, doc, "MatchString", re.MatchString(s), std.MatchString(s))
			checkSame(t, expr, doc, "Format.findAll", detectors.FormatFindAllForTest(f, doc), want)
		}
	}
	t.Logf("%d patterns, %d anchored, %d matches compared", len(patterns), anchored, matched)
	if anchored < len(patterns)/2 {
		t.Fatalf("only %d of %d patterns anchored", anchored, len(patterns))
	}
	if matched < anchored {
		t.Fatalf("too few matches: %d for %d patterns", matched, anchored)
	}
}

func checkSame(t *testing.T, expr string, doc []byte, method string, got, want any) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	// FindAllString and friends return nil vs empty identically for
	// callers; normalise before failing.
	if reflect.ValueOf(got).Len() == 0 && reflect.ValueOf(want).Len() == 0 {
		return
	}
	t.Fatalf("%s differs for %q\ngot  %v\nwant %v\ninput %q", method, expr, got, want, doc)
}

// FuzzAnchorNarrowing compares the narrowed search with the standard
// library on arbitrary inputs for patterns covering literal anchors with
// bounded, class-walked and alternated extents, and class-run anchors.
func FuzzAnchorNarrowing(f *testing.F) {
	exprs := []string{
		`\b(AC[a-f0-9]{32})\b`,
		`(?im)(?:^|[^a-zA-Z])(?:password|passwd|pwd)(?:[^a-z0-9_][^\n=]*)?\s*=\s*["']?([^"'\n\r${}<>%\[\]{} ]{4,64})["']?`,
		`(?i)\$([a-z0-9_]*(?:password|passwd|pwd|secret)[a-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)")`,
		`(?m)^[ \t]*SECRET_KEY[ \t]*=[ \t]*['"]([^'"\r\n]{8,256})['"][ \t]*$`,
		`\b([a-f0-9]{40,80})\b`,
		`\b([0-9]{6,12}:[A-Za-z0-9_-]{30,})\b`,
		`(?i)k[a-z]{2}\b`,
		`-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END`,
		`(?s)é.{0,3}ab`,
	}
	for i := range exprs {
		// Assembled at run time so the fixture is not itself a finding.
		seed := "x pass" + "word = 'hunter" + "22' \u212a\u017f A" + "C" + strings.Repeat("0123456789abcdef", 2) + " é ab"
		f.Add(uint8(i), []byte(seed))
	}
	res := make([]*detectors.Regexp, len(exprs))
	stds := make([]*regexp.Regexp, len(exprs))
	for i, e := range exprs {
		res[i], stds[i] = detectors.MustCompile(e), regexp.MustCompile(e)
	}
	f.Fuzz(func(t *testing.T, which uint8, doc []byte) {
		i := int(which) % len(exprs)
		checkSame(t, exprs[i], doc, "FindAllSubmatchIndex", res[i].FindAllSubmatchIndex(doc, -1), stds[i].FindAllSubmatchIndex(doc, -1))
		checkSame(t, exprs[i], doc, "FindIndex", res[i].FindIndex(doc), stds[i].FindIndex(doc))
	})
}

// TestAnchorBuildCost bounds anchor construction over every pattern: an
// analysis that is quadratic in expanded repeats (x{0,1000}) once added
// ~0.3 CPU-s to each process start (#1034).
func TestAnchorBuildCost(t *testing.T) {
	patterns := constantPatterns(t)
	start := time.Now()
	for _, expr := range patterns {
		detectors.AnchoredForTest(expr)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("building %d anchors took %v", len(patterns), d)
	}
}
