package git

import (
	"bytes"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// prepareFullRef is prepare before #1046: every record of both files is
// split and classified, then the common ends are trimmed by class.
func prepareFullRef(x *xdiffer, a, b []byte) {
	x.len1, x.len2 = x.len1[:0], x.len2[:0]
	x.f1.recs = xdlSplitRecords(a, x.f1.recs)
	x.f2.recs = xdlSplitRecords(b, x.f2.recs)
	x.classes.reset(len(x.f1.recs) + len(x.f2.recs))
	x.f1.mph = x.classify(1, x.f1.recs, x.f1.mph[:0])
	x.f2.mph = x.classify(2, x.f2.recs, x.f2.mph[:0])
	for _, f := range []*xdFile{&x.f1, &x.f2} {
		n := len(f.recs) + 2
		f.changed = make([]bool, n)
		f.ref = f.ref[:0]
		f.dstart = 0
		f.dend = len(f.recs) - 1
	}
	x.trimEndsRef()
	x.cleanupRecords()
}

func (x *xdiffer) trimEndsRef() {
	f1, f2 := &x.f1, &x.f2
	lim := min(len(f1.recs), len(f2.recs))
	i := 0
	for ; i < lim; i++ {
		if f1.mph[i] != f2.mph[i] {
			break
		}
	}
	f1.dstart, f2.dstart = i, i
	lim -= i
	r1, r2 := len(f1.recs)-1, len(f2.recs)-1
	for i = 0; i < lim; i, r1, r2 = i+1, r1-1, r2-1 {
		if f1.mph[r1] != f2.mph[r2] {
			break
		}
	}
	f1.dend = len(f1.recs) - i - 1
	f2.dend = len(f2.recs) - i - 1
}

// xdRandomPair builds an old/new pair that shares long heads and tails,
// repeats lines (so occurrence counts cross the head/tail boundary), and
// varies trailing newlines.
func xdRandomPair(r *rand.Rand) ([]byte, []byte) {
	vocab := []string{"", "a", "b", "}", "\t}", "func f() {", "return nil", "x := 1", "ab", "a\r", " "}
	for range r.Intn(4) {
		vocab = append(vocab, strings.Repeat("z", r.Intn(70)))
	}
	line := func() string { return vocab[r.Intn(len(vocab))] }
	var head, mid1, mid2, tail strings.Builder
	for range r.Intn(40) {
		head.WriteString(line() + "\n")
	}
	for range r.Intn(8) {
		mid1.WriteString(line() + "\n")
	}
	for range r.Intn(8) {
		mid2.WriteString(line() + "\n")
	}
	for range r.Intn(40) {
		tail.WriteString(line() + "\n")
	}
	a := head.String() + mid1.String() + tail.String()
	b := head.String() + mid2.String() + tail.String()
	trim := func(s string) string {
		if r.Intn(3) == 0 && len(s) > 0 && s[len(s)-1] == '\n' {
			return s[:len(s)-1]
		}
		if r.Intn(5) == 0 {
			return s + line()
		}
		return s
	}
	return []byte(trim(a)), []byte(trim(b))
}

func TestXDiffPrepareMatchesFullClassify(t *testing.T) {
	r := rand.New(rand.NewSource(1046))
	var fast, ref xdiffer
	ref.prepareRef = prepareFullRef
	for i := range 200000 {
		var a, b []byte
		if i%50 == 1 {
			a, b = xdRandomPair(r)
			if r.Intn(2) == 0 {
				a = nil
			} else {
				b = nil
			}
		} else if i%4 == 0 {
			vocab := []string{"a", "b", "c", "}", "", "a "}
			a = randomLines(r, r.Intn(30), vocab)
			b = mutate(r, a, vocab)
		} else {
			a, b = xdRandomPair(r)
		}
		if bytes.Equal(a, b) {
			continue
		}
		got, gotAny := fast.unified(nil, a, b)
		want, wantAny := ref.unified(nil, a, b)
		if gotAny != wantAny || !bytes.Equal(got, want) {
			t.Fatalf("case %d: a=%q b=%q\ngot:\n%s\nwant:\n%s", i, a, b, got, want)
		}
		// The recorded line ends are exactly the newline splits the line
		// feed used to compute (#1046).
		var split []int
		for j, c := range got {
			if c == '\n' {
				split = append(split, j+1)
			}
		}
		if gotAny && !slices.Equal(fast.ends, split) {
			t.Fatalf("case %d: line ends %v, want %v for %q", i, fast.ends, split, got)
		}
		for k, pair := range [][2]*xdFile{{&fast.f1, &ref.f1}, {&fast.f2, &ref.f2}} {
			g, w := pair[0], pair[1]
			if g.dstart != w.dstart || g.dend != w.dend || len(g.recs) != len(w.recs) {
				t.Fatalf("case %d file %d: bounds %d..%d/%d, want %d..%d/%d", i, k+1, g.dstart, g.dend, len(g.recs), w.dstart, w.dend, len(w.recs))
			}
			for j := range g.recs {
				if !bytes.Equal(g.recs[j], w.recs[j]) {
					t.Fatalf("case %d file %d: record %d = %q, want %q", i, k+1, j, g.recs[j], w.recs[j])
				}
			}
		}
	}
}
