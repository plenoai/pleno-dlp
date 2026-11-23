package detectors

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"sort"
	"sync"
	"unicode"
	"unicode/utf8"
)

// anchor narrows a regexp search to the candidate spans around a literal
// that every match must contain (#1034).
//
// Detector windows are up to 4 KiB around a keyword hit, and Go's regexp
// walks every byte of them with its NFA or backtracker. An anchor is a
// literal set such that every match contains an occurrence of one member.
// The part of a match before that occurrence is bounded by left and the
// part after it by right: at most n bytes, each drawn from class. So every
// match lies inside the span reached by walking outward from some
// occurrence while those bounds hold, and running the regexp on the
// merged spans alone finds exactly the matches a whole-input run finds:
//
//   - each span is widened by utf8.UTFMax bytes and then to rune starts,
//     so the regexp decodes the same runes and its context-sensitive
//     assertions (\b, \B, (?m)^, (?m)$) see the same neighbouring runes
//     as in the whole input; patterns with \A or \z get no anchor;
//   - a match found inside a span still contains an occurrence and obeys
//     the bounds, so it never touches a widened edge: it is a real match;
//   - overlapping spans merge, so every candidate match starting at a
//     position lies inside the one span containing that position, and
//     leftmost-first selection at each start sees the same alternatives;
//   - every match is non-empty (it contains a literal), so FindAll's
//     empty-match rule never applies, and spans are visited in order, so
//     the concatenated results equal the whole-input sequence.
//
// Case-insensitive literals are searched with ASCII folding; inputs that
// contain the only non-ASCII runes folding to ASCII letters (U+017F,
// U+212A) are searched whole.
type anchor struct {
	lits        [][]byte
	fold        bool
	left, right extent
	// run, when lits is empty, anchors on maximal runs of at least run.n
	// bytes allowed by run.
	run step
}

// extent bounds one side of a match as a sequence of steps, nearest to
// the literal first. Each step covers at most n bytes (n == unbounded: no
// limit), every byte in class or >= 0x80, or any byte when any is set.
//
// Walking the steps greedily outward is an exact upper bound on how far
// the side reaches: the positions reachable after a step form an interval
// starting at the literal, and its far end is reached by walking the step
// from the previous far end.
type extent []step

type step struct {
	n     int
	class [256]bool
	any   bool
	// alts, when set, replaces the fields above: the step matches one of
	// the alternatives, and walking it reaches the farthest of theirs.
	alts []extent
}

// anchorMinLit is the shortest literal worth anchoring on: a one-byte
// literal occurs too often to narrow anything.
const anchorMinLit = 2

// unbounded marks a repetition with no upper bound.
const unbounded = -1

func buildAnchor(expr string) *anchor {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	// The tree stays unsimplified: Simplify expands x{0,1000} into a
	// thousand nested optional nodes, and the analysis handles OpRepeat
	// directly.
	if hasTextAnchor(re) {
		return nil
	}
	b := &anchorBuilder{facts: map[*syntax.Regexp]*facts{}, maxLen: map[*syntax.Regexp]int{}}
	a, ok := b.findAnchor(re)
	if ok && a.left.bounded() && a.left.score()+a.right.score() < scoreClass {
		return &a
	}
	// Without a literal anchor whose left side is bounded, a pattern whose
	// every byte comes from one class, such as \b([a-f0-9]{40,80})\b,
	// still matches only inside a long enough run of that class.
	if f := b.analyze(re); (!ok || !a.left.bounded()) && f.pure && f.minLen >= minRunBytes {
		return &anchor{run: step{n: f.minLen, class: f.class}}
	}
	if !ok || !a.left.bounded() {
		return nil
	}
	return &a
}

// bounded reports whether walking the extent can stop before the input
// edge.
func (e extent) bounded() bool { return e.score() < scoreAny }

func hasTextAnchor(re *syntax.Regexp) bool {
	if re.Op == syntax.OpBeginText || re.Op == syntax.OpEndText {
		return true
	}
	for _, s := range re.Sub {
		if hasTextAnchor(s) {
			return true
		}
	}
	return false
}

// runeWidth is the widest UTF-8 encoding among runes r matches; invalid
// bytes match as U+FFFD one byte at a time, within the bound.
func runeWidth(r rune, fold bool) int {
	w := utf8.RuneLen(r)
	if w < 0 {
		w = utf8.UTFMax
	}
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if fw := utf8.RuneLen(f); fw > w {
				w = fw
			}
		}
	}
	return w
}

// anchorBuilder memoizes per-node analysis while one pattern's anchor is
// chosen; without it the search re-analyzes every subtree at each level.
type anchorBuilder struct {
	facts  map[*syntax.Regexp]*facts
	maxLen map[*syntax.Regexp]int
}

func (b *anchorBuilder) analyze(re *syntax.Regexp) *facts {
	f, ok := b.facts[re]
	if !ok {
		v := analyze(re)
		f = &v
		b.facts[re] = f
	}
	return f
}

// longest is the longest match of re in bytes, or unbounded.
func (b *anchorBuilder) longest(re *syntax.Regexp) int {
	n, ok := b.maxLen[re]
	if !ok {
		n = b.computeLongest(re)
		b.maxLen[re] = n
	}
	return n
}

func (b *anchorBuilder) computeLongest(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary, syntax.OpNoMatch:
		return 0
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += runeWidth(r, re.Flags&syntax.FoldCase != 0)
		}
		return n
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0
		}
		return runeWidth(re.Rune[len(re.Rune)-1], false)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return b.longest(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return mulBound(b.longest(re.Sub[0]), unbounded)
	case syntax.OpRepeat:
		return mulBound(b.longest(re.Sub[0]), re.Max)
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			n = addBound(n, b.longest(s))
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			n = maxBound(n, b.longest(s))
		}
		return n
	}
	return unbounded
}

func addBound(a, b int) int {
	if a == unbounded || b == unbounded {
		return unbounded
	}
	return a + b
}

func maxBound(a, b int) int {
	if a == unbounded || b == unbounded {
		return unbounded
	}
	return max(a, b)
}

// mulBound is a repeated up to k times (k < 0: unbounded).
func mulBound(a, k int) int {
	if a == 0 || k == 0 {
		return 0
	}
	if a == unbounded || k < 0 {
		return unbounded
	}
	return a * k
}

// nodeExtent is the extent covering any match of re, walked forward
// (rev false) or backward (rev true). Concatenations keep one step per
// element so that a closing quote bounds the step before it.
func (b *anchorBuilder) nodeExtent(re *syntax.Regexp, rev bool) extent {
	switch re.Op {
	case syntax.OpCapture:
		return b.nodeExtent(re.Sub[0], rev)
	case syntax.OpQuest:
		// Every step may consume nothing, so the optional node's own
		// steps already cover its absence.
		return b.nodeExtent(re.Sub[0], rev)
	case syntax.OpAlternate:
		st := step{alts: make([]extent, len(re.Sub))}
		for i, sub := range re.Sub {
			st.alts[i] = b.nodeExtent(sub, rev)
		}
		return extent{st}
	case syntax.OpConcat:
		var e extent
		for i := range re.Sub {
			j := i
			if rev {
				j = len(re.Sub) - 1 - i
			}
			e = append(e, b.nodeExtent(re.Sub[j], rev)...)
		}
		return e
	}
	return extent{b.nodeStep(re)}
}

func (b *anchorBuilder) nodeStep(re *syntax.Regexp) step {
	st := step{n: b.longest(re)}
	if f := b.analyze(re); f.pure {
		st.class = f.class
	} else {
		st.any = true
	}
	return st
}

// union is an extent covering both e and o.
func (e extent) union(o extent) extent {
	return extent{{alts: []extent{e, o}}}
}

// score orders extents: bounded byte counts first, then class-limited
// walks, then unbounded ones.
func (e extent) score() int {
	s := 0
	for i := range e {
		if alts := e[i].alts; alts != nil {
			worst := 0
			for _, x := range alts {
				worst = max(worst, x.score())
			}
			if worst >= scoreClass {
				if worst == scoreAny {
					return scoreAny
				}
				s = scoreClass
			} else if s < scoreClass {
				s += worst
			}
			continue
		}
		switch {
		case e[i].n == unbounded && e[i].any:
			return scoreAny
		case e[i].n == unbounded:
			s = scoreClass
		case s < scoreClass:
			s += e[i].n
		}
	}
	return s
}

const (
	scoreClass = 1 << 20
	scoreAny   = 1 << 30
)

// better reports whether a likely narrows more than b.
func (a anchor) better(b anchor) bool {
	sa, sb := a.left.score()+a.right.score(), b.left.score()+b.right.score()
	if sa != sb {
		return sa < sb
	}
	return shortest(a.lits) > shortest(b.lits)
}

func shortest(ls [][]byte) int {
	n := -1
	for _, l := range ls {
		if n < 0 || len(l) < n {
			n = len(l)
		}
	}
	return n
}

// findAnchor returns the best anchor for re, extents relative to the
// match of re itself.
func (b *anchorBuilder) findAnchor(re *syntax.Regexp) (anchor, bool) {
	// A node whose whole language is a small literal set anchors itself
	// with empty extents; this also covers alternations the parser
	// factored into prefix trees such as p(?:ass(?:word|wd)|wd).
	if f := b.analyze(re); f.exactOK && len(f.exact) > 0 && len(f.exact) <= maxLitSet && shortest(f.exact) >= anchorMinLit {
		return anchor{lits: dedupLits(f.exact), fold: f.exactFold}, true
	}
	switch re.Op {
	case syntax.OpCapture:
		return b.findAnchor(re.Sub[0])
	case syntax.OpPlus, syntax.OpRepeat:
		if re.Op == syntax.OpRepeat && re.Min < 1 {
			return anchor{}, false
		}
		a, ok := b.findAnchor(re.Sub[0])
		if !ok {
			return a, false
		}
		rest := b.nodeStep(re.Sub[0])
		k := unbounded
		if re.Op == syntax.OpRepeat && re.Max >= 0 {
			k = re.Max - 1
		}
		rest.n = mulBound(rest.n, k)
		a.left = append(a.left, rest)
		a.right = append(a.right, rest)
		return a, true
	case syntax.OpConcat:
		var best anchor
		found := false
		for i, s := range re.Sub {
			a, ok := b.findAnchor(s)
			if !ok {
				continue
			}
			for j := i - 1; j >= 0; j-- {
				a.left = append(a.left, b.nodeExtent(re.Sub[j], true)...)
			}
			for _, p := range re.Sub[i+1:] {
				a.right = append(a.right, b.nodeExtent(p, false)...)
			}
			if !found || a.better(best) {
				best, found = a, true
			}
		}
		return best, found
	case syntax.OpAlternate:
		var out anchor
		for i, s := range re.Sub {
			a, ok := b.findAnchor(s)
			if !ok || (i > 0 && a.fold != out.fold) {
				return anchor{}, false
			}
			if i == 0 {
				out = anchor{fold: a.fold, left: a.left, right: a.right}
			} else {
				out.left = out.left.union(a.left)
				out.right = out.right.union(a.right)
			}
			out.lits = append(out.lits, a.lits...)
		}
		out.lits = dedupLits(out.lits)
		return out, len(out.lits) > 0 && len(out.lits) <= maxLitSet
	}
	return anchor{}, false
}

func dedupLits(ls [][]byte) [][]byte {
	out := make([][]byte, 0, len(ls))
	for _, l := range ls {
		dup := false
		for _, o := range out {
			if bytes.Equal(o, l) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, l)
		}
	}
	return out
}

// span is a half-open byte range [lo, hi).
type span struct{ lo, hi int }

type spanBuf struct{ s []span }

var spanPool = sync.Pool{New: func() any { return &spanBuf{s: make([]span, 0, 32)} }}

// narrowMaxCover is the share of the input (in quarters) above which
// narrowing is skipped: scanning most of the input piecewise saves
// nothing.
const narrowMaxCover = 3

// allowed reports whether byte c may be part of the step.
func (st *step) allowed(c byte) bool { return st.any || c >= utf8.RuneSelf || st.class[c] }

// walkLeft returns the lowest start the side can reach before pos.
func (e extent) walkLeft(b []byte, pos int) int {
	for i := range e {
		st := &e[i]
		if st.alts != nil {
			far := pos
			for _, x := range st.alts {
				far = min(far, x.walkLeft(b, pos))
			}
			pos = far
			continue
		}
		lo := 0
		if st.n != unbounded {
			lo = max(pos-st.n, 0)
		}
		if st.any {
			pos = lo
			continue
		}
		for pos > lo && st.allowed(b[pos-1]) {
			pos--
		}
	}
	return pos
}

// walkRight returns the highest end the side can reach after pos.
func (e extent) walkRight(b []byte, pos int) int {
	for i := range e {
		st := &e[i]
		if st.alts != nil {
			far := pos
			for _, x := range st.alts {
				far = max(far, x.walkRight(b, pos))
			}
			pos = far
			continue
		}
		hi := len(b)
		if st.n != unbounded {
			hi = min(pos+st.n, len(b))
		}
		if st.any {
			pos = hi
			continue
		}
		for pos < hi && st.allowed(b[pos]) {
			pos++
		}
	}
	return pos
}

// spans returns the merged candidate spans for b, or ok=false when b must
// be searched whole. An empty result with ok=true means b holds no match.
func (a *anchor) spans(b []byte, buf *spanBuf) (out []span, ok bool) {
	if a.fold {
		for _, u := range unicodeFoldsOfASCII {
			if bytes.Contains(b, u) {
				return nil, false
			}
		}
	}
	out = buf.s[:0]
	if len(a.lits) == 0 {
		return a.runSpans(b, buf)
	}
	budget := 2 * len(b) // bytes walked before giving up on narrowing
	for _, l := range a.lits {
		for pos := 0; pos+len(l) <= len(b); {
			var i int
			if a.fold {
				i = indexFoldASCIIPos(b[pos:], l)
			} else {
				i = bytes.Index(b[pos:], l)
			}
			if i < 0 {
				break
			}
			occ := pos + i
			pos = occ + 1
			end := occ + len(l)
			lo := a.left.walkLeft(b, occ)
			hi := a.right.walkRight(b, end)
			budget -= (occ - lo) + (hi - end)
			if budget < 0 {
				buf.s = out
				return nil, false
			}
			out = append(out, span{runeStartBefore(b, lo-utf8.UTFMax), runeStartAfter(b, hi+utf8.UTFMax)})
		}
	}
	buf.s = out
	if len(out) == 0 {
		return out, true
	}
	if len(a.lits) > 1 {
		sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })
	}
	m, covered := 0, 0
	for _, s := range out[1:] {
		if s.lo <= out[m].hi {
			out[m].hi = max(out[m].hi, s.hi)
			continue
		}
		covered += out[m].hi - out[m].lo
		m++
		out[m] = s
	}
	covered += out[m].hi - out[m].lo
	out = out[:m+1]
	buf.s = out
	if covered > len(b)/4*narrowMaxCover {
		return nil, false
	}
	return out, true
}

// runSpans returns the maximal runs of allowed bytes that are long
// enough to hold a match, widened like literal spans.
func (a *anchor) runSpans(b []byte, buf *spanBuf) ([]span, bool) {
	out := buf.s[:0]
	covered := 0
	for i := 0; i < len(b); {
		if !a.run.allowed(b[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(b) && a.run.allowed(b[j]) {
			j++
		}
		if j-i >= a.run.n {
			lo, hi := runeStartBefore(b, i-utf8.UTFMax), runeStartAfter(b, j+utf8.UTFMax)
			if n := len(out); n > 0 && lo <= out[n-1].hi {
				covered += hi - out[n-1].hi
				out[n-1].hi = hi
			} else {
				covered += hi - lo
				out = append(out, span{lo, hi})
			}
		}
		i = j
	}
	buf.s = out
	if covered > len(b)/4*narrowMaxCover {
		return nil, false
	}
	return out, true
}

// runeStartBefore clamps i to b and moves it back to a byte that is not a
// UTF-8 continuation byte: forward decoding always starts a rune there.
func runeStartBefore(b []byte, i int) int {
	if i <= 0 {
		return 0
	}
	for i > 0 && b[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

// runeStartAfter clamps i to b and moves it forward past continuation
// bytes.
func runeStartAfter(b []byte, i int) int {
	for i < len(b) && b[i]&0xC0 == 0x80 {
		i++
	}
	return min(i, len(b))
}

// indexFoldASCIIPos is bytes.Index with ASCII case folding for a
// lower-case literal.
func indexFoldASCIIPos(b, lit []byte) int {
	c0 := lit[0]
	u0 := c0
	if 'a' <= c0 && c0 <= 'z' {
		u0 = c0 - 'a' + 'A'
	}
	last := len(b) - len(lit) + 1
	for i := 0; i < last; i++ {
		j := bytes.IndexByte(b[i:last], c0)
		if u0 != c0 {
			if k := bytes.IndexByte(b[i:last], u0); k >= 0 && (j < 0 || k < j) {
				j = k
			}
		}
		if j < 0 {
			return -1
		}
		i += j
		if equalFoldASCII(b[i+1:i+len(lit)], lit[1:]) {
			return i
		}
	}
	return -1
}

// narrowAll runs find over a's candidate spans of b (or b whole when a is
// nil or narrowing does not apply) and returns at most n match index
// slices (n < 0: all) relative to b.
func narrowAll(a *anchor, b []byte, n int, find func([]byte, int) [][]int) [][]int {
	if n == 0 {
		return nil
	}
	if a == nil {
		return find(b, n)
	}
	buf := spanPool.Get().(*spanBuf)
	defer spanPool.Put(buf)
	sp, ok := a.spans(b, buf)
	if !ok {
		return find(b, n)
	}
	var out [][]int
	for _, s := range sp {
		rem := -1
		if n > 0 {
			rem = n - len(out)
		}
		ms := find(b[s.lo:s.hi], rem)
		for _, m := range ms {
			for j := range m {
				if m[j] >= 0 {
					m[j] += s.lo
				}
			}
		}
		out = append(out, ms...)
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}

// findAllSubmatchIndexNarrow is re.FindAllSubmatchIndex(b, n) restricted
// to a's candidate spans.
func findAllSubmatchIndexNarrow(re *regexp.Regexp, a *anchor, b []byte, n int) [][]int {
	return narrowAll(a, b, n, re.FindAllSubmatchIndex)
}
