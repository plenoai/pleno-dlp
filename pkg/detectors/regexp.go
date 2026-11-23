package detectors

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
	"unsafe"
)

// Regexp is a *regexp.Regexp guarded by an exact necessary-condition
// prefilter derived from the pattern's syntax tree (#984).
//
// Most detector windows are reached through a short keyword and contain
// no match, yet the regexp engine still walks every byte. Before running
// the regexp, the matching methods below check conditions every match
// must satisfy: at least one literal from each required literal set, and
// a run of at least N bytes drawn from a required byte class (for
// example 32 hex digits for `\b([a-f0-9]{32})\b`). When a condition
// fails the input cannot contain a match, so the method returns exactly
// what the regexp would return for a non-matching input.
//
// The conditions are evaluated only on ASCII inputs. Any byte >= 0x80
// bypasses the prefilter, so case folding through non-ASCII runes
// (U+017F, U+212A) and multi-byte class members never affect results.
type Regexp struct {
	*regexp.Regexp
	pre *prefilter
}

// MustCompile is regexp.MustCompile plus the prefilter.
func MustCompile(expr string) *Regexp {
	return newRegexp(regexp.MustCompile(expr), expr)
}

// Compile is regexp.Compile plus the prefilter.
func Compile(expr string) (*Regexp, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return newRegexp(re, expr), nil
}

// WrapRegexp attaches a prefilter to an already-compiled regexp.
func WrapRegexp(re *regexp.Regexp) *Regexp {
	return newRegexp(re, re.String())
}

func newRegexp(re *regexp.Regexp, expr string) *Regexp {
	return &Regexp{Regexp: re, pre: buildPrefilter(expr)}
}

// Std returns the underlying standard-library regexp.
func (r *Regexp) Std() *regexp.Regexp { return r.Regexp }

// mayMatch reports false only when b cannot contain a match.
func (r *Regexp) mayMatch(b []byte) bool { return r.pre == nil || r.pre.mayMatch(b) }

func (r *Regexp) mayMatchString(s string) bool {
	return r.pre == nil || r.pre.mayMatch(stringBytes(s))
}

func (r *Regexp) Match(b []byte) bool { return r.mayMatch(b) && r.Regexp.Match(b) }
func (r *Regexp) MatchString(s string) bool {
	return r.mayMatchString(s) && r.Regexp.MatchString(s)
}

func (r *Regexp) Find(b []byte) []byte {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.Find(b)
}

func (r *Regexp) FindIndex(b []byte) []int {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindIndex(b)
}

func (r *Regexp) FindSubmatch(b []byte) [][]byte {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindSubmatch(b)
}

func (r *Regexp) FindSubmatchIndex(b []byte) []int {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindSubmatchIndex(b)
}

func (r *Regexp) FindAll(b []byte, n int) [][]byte {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindAll(b, n)
}

func (r *Regexp) FindAllIndex(b []byte, n int) [][]int {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindAllIndex(b, n)
}

func (r *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindAllSubmatch(b, n)
}

func (r *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	if !r.mayMatch(b) {
		return nil
	}
	return r.Regexp.FindAllSubmatchIndex(b, n)
}

func (r *Regexp) FindString(s string) string {
	if !r.mayMatchString(s) {
		return ""
	}
	return r.Regexp.FindString(s)
}

func (r *Regexp) FindStringIndex(s string) []int {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindStringIndex(s)
}

func (r *Regexp) FindStringSubmatch(s string) []string {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindStringSubmatch(s)
}

func (r *Regexp) FindStringSubmatchIndex(s string) []int {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindStringSubmatchIndex(s)
}

func (r *Regexp) FindAllString(s string, n int) []string {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindAllString(s, n)
}

func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindAllStringIndex(s, n)
}

func (r *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindAllStringSubmatch(s, n)
}

func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if !r.mayMatchString(s) {
		return nil
	}
	return r.Regexp.FindAllStringSubmatchIndex(s, n)
}

// prefilter is a conjunction of necessary conditions.
type prefilter struct {
	lits []litSet // every set must have one member present
	runs []byteRun
}

// litSet is satisfied when any literal occurs; fold literals are stored
// lower-case and matched ASCII case-insensitively.
type litSet struct {
	lits [][]byte
	fold bool
}

// byteRun is satisfied by min consecutive bytes from class.
type byteRun struct {
	class [256]bool
	min   int
}

const (
	maxLitSet   = 32
	minRunBytes = 8 // shorter runs are too common to pay for the scan
)

func (p *prefilter) mayMatch(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return true
		}
	}
	for i := range p.runs {
		if !p.runs[i].present(b) {
			return false
		}
	}
	for i := range p.lits {
		if !p.lits[i].present(b) {
			return false
		}
	}
	return true
}

func (r *byteRun) present(b []byte) bool {
	n := 0
	for _, c := range b {
		if r.class[c] {
			n++
			if n >= r.min {
				return true
			}
		} else {
			n = 0
		}
	}
	return false
}

func (s *litSet) present(b []byte) bool {
	for _, l := range s.lits {
		if s.fold {
			if indexFoldASCII(b, l) {
				return true
			}
		} else if bytes.Contains(b, l) {
			return true
		}
	}
	return false
}

// indexFoldASCII reports whether lower-case ASCII lit occurs in b,
// ignoring ASCII case.
func indexFoldASCII(b, lit []byte) bool {
	if len(lit) == 0 {
		return true
	}
	if len(b) < len(lit) {
		return false
	}
	c0 := lit[0]
	u0 := c0
	if 'a' <= c0 && c0 <= 'z' {
		u0 = c0 - 'a' + 'A'
	}
	hay := b[:len(b)-len(lit)+1]
	// nextL/nextU cache the next occurrence of each case of the first
	// byte so every byte is searched at most once per case.
	nextL, nextU := -2, -2
	if u0 == c0 {
		nextU = -1
	}
	for i := 0; i < len(hay); {
		if nextL != -1 && nextL < i {
			if j := bytes.IndexByte(hay[i:], c0); j >= 0 {
				nextL = i + j
			} else {
				nextL = -1
			}
		}
		if nextU != -1 && nextU < i {
			if j := bytes.IndexByte(hay[i:], u0); j >= 0 {
				nextU = i + j
			} else {
				nextU = -1
			}
		}
		k := nextL
		if k < 0 || (nextU >= 0 && nextU < k) {
			k = nextU
		}
		if k < 0 {
			return false
		}
		if equalFoldASCII(b[k+1:k+len(lit)], lit[1:]) {
			return true
		}
		i = k + 1
	}
	return false
}

func equalFoldASCII(a, lower []byte) bool {
	for i, c := range a {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

func buildPrefilter(expr string) *prefilter {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	f := analyze(re)
	p := &prefilter{}
	for _, l := range f.lits {
		if len(l.lits) > 0 && len(l.lits) <= maxLitSet && !l.hasEmpty() {
			p.lits = append(p.lits, l)
		}
	}
	for _, r := range f.runs {
		if r.min >= minRunBytes && !r.universal() {
			p.runs = append(p.runs, r)
		}
	}
	if len(p.lits) == 0 && len(p.runs) == 0 {
		return nil
	}
	return p
}

func (s litSet) hasEmpty() bool {
	for _, l := range s.lits {
		if len(l) == 0 {
			return true
		}
	}
	return false
}

func (r *byteRun) universal() bool {
	for _, ok := range r.class {
		if !ok {
			return false
		}
	}
	return true
}

// facts are the necessary conditions known for a subexpression.
//
// pure reports that every string the node matches consists only of bytes
// in class (ASCII projection) and has at least minLen bytes; pure nodes
// next to each other in a concatenation merge into one longer run. exact
// is the node's full literal language when it is a small finite set.
type facts struct {
	lits []litSet
	runs []byteRun

	pure   bool
	class  [256]bool
	minLen int

	exact     [][]byte
	exactOK   bool
	exactFold bool
}

func analyze(re *syntax.Regexp) facts {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return facts{pure: true, exact: [][]byte{{}}, exactOK: true}
	case syntax.OpLiteral:
		return literalFacts(re)
	case syntax.OpCharClass:
		var f facts
		f.pure = true
		f.minLen = 1
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for c := lo; c <= hi && c < utf8.RuneSelf; c++ {
				f.class[c] = true
			}
		}
		return f
	case syntax.OpAnyCharNotNL:
		f := facts{pure: true, minLen: 1}
		for c := 0; c < utf8.RuneSelf; c++ {
			f.class[c] = c != '\n'
		}
		return f
	case syntax.OpAnyChar:
		f := facts{pure: true, minLen: 1}
		for c := 0; c < utf8.RuneSelf; c++ {
			f.class[c] = true
		}
		return f
	case syntax.OpCapture:
		return analyze(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		sub := analyze(re.Sub[0])
		f := facts{pure: sub.pure, class: sub.class}
		if sub.exactOK && re.Op == syntax.OpQuest {
			f.exact = append([][]byte{{}}, sub.exact...)
			f.exactOK = len(f.exact) <= maxLitSet
			f.exactFold = sub.exactFold
		}
		return f
	case syntax.OpPlus:
		sub := analyze(re.Sub[0])
		sub.exactOK = false
		sub.exact = nil
		return sub
	case syntax.OpRepeat:
		sub := analyze(re.Sub[0])
		if re.Min == 0 {
			return facts{pure: sub.pure, class: sub.class}
		}
		f := sub
		f.minLen = sub.minLen * re.Min
		if f.pure {
			f.runs = append(append([]byteRun(nil), sub.runs...), byteRun{class: sub.class, min: f.minLen})
		}
		f.exactOK = false
		f.exact = nil
		return f
	case syntax.OpConcat:
		return concatFacts(re.Sub)
	case syntax.OpAlternate:
		return alternateFacts(re.Sub)
	}
	return facts{}
}

func literalFacts(re *syntax.Regexp) facts {
	fold := re.Flags&syntax.FoldCase != 0
	var lit []byte
	f := facts{pure: true}
	for _, r := range re.Rune {
		if r >= utf8.RuneSelf {
			// Non-ASCII literals never match an ASCII input; the
			// prefilter only runs on ASCII inputs, so an unsatisfiable
			// condition would be exact, but keep it simple and drop
			// literal and run facts.
			return facts{}
		}
		c := byte(r)
		if fold {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			f.class[c] = true
			if 'a' <= c && c <= 'z' {
				f.class[c-'a'+'A'] = true
			}
		} else {
			f.class[c] = true
		}
		lit = append(lit, c)
	}
	f.minLen = len(lit)
	f.exact = [][]byte{lit}
	f.exactOK = true
	f.exactFold = fold
	if len(lit) > 0 {
		f.lits = []litSet{{lits: [][]byte{lit}, fold: fold}}
	}
	return f
}

func concatFacts(subs []*syntax.Regexp) facts {
	var f facts
	f.pure = true
	f.exact = [][]byte{{}}
	f.exactOK = true
	exactFoldSet := false

	var run byteRun
	flush := func() {
		if run.min > 0 {
			f.runs = append(f.runs, run)
		}
		run = byteRun{}
	}
	for _, s := range subs {
		sf := analyze(s)
		f.lits = append(f.lits, sf.lits...)
		f.runs = append(f.runs, sf.runs...)
		if sf.pure {
			for c, ok := range sf.class {
				if ok {
					run.class[c] = true
					f.class[c] = true
				}
			}
			run.min += sf.minLen
		} else {
			flush()
			f.pure = false
		}
		f.minLen += sf.minLen
		if f.exactOK && sf.exactOK {
			if !allEmpty(sf.exact) {
				if exactFoldSet && f.exactFold != sf.exactFold {
					f.exactOK = false
				}
				f.exactFold, exactFoldSet = sf.exactFold, true
			}
			if f.exactOK {
				f.exact = crossLits(f.exact, sf.exact)
				f.exactOK = f.exact != nil
			}
		} else {
			f.exactOK = false
		}
	}
	flush()
	if f.exactOK && !allEmpty(f.exact) {
		f.lits = append(f.lits, litSet{lits: f.exact, fold: f.exactFold})
	}
	return f
}

func allEmpty(ls [][]byte) bool {
	for _, l := range ls {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

func crossLits(a, b [][]byte) [][]byte {
	if len(a)*len(b) > maxLitSet {
		return nil
	}
	out := make([][]byte, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, append(append([]byte(nil), x...), y...))
		}
	}
	return out
}

func alternateFacts(subs []*syntax.Regexp) facts {
	var f facts
	f.pure = true
	f.exactOK = true
	exactFoldSet := false
	litsOK := true
	var union [][]byte
	unionFold, unionFoldSet := false, false
	minRun := -1
	var runClass [256]bool
	for i, s := range subs {
		sf := analyze(s)
		if !sf.pure {
			f.pure = false
		}
		for c, ok := range sf.class {
			if ok {
				f.class[c] = true
			}
		}
		if i == 0 || sf.minLen < f.minLen {
			f.minLen = sf.minLen
		}
		// Exact language union; the empty string is fold-neutral.
		if f.exactOK && sf.exactOK {
			if !allEmpty(sf.exact) {
				if exactFoldSet && f.exactFold != sf.exactFold {
					f.exactOK = false
				}
				f.exactFold, exactFoldSet = sf.exactFold, true
			}
			if f.exactOK {
				f.exact = append(f.exact, sf.exact...)
				f.exactOK = len(f.exact) <= maxLitSet
			}
		} else {
			f.exactOK = false
		}
		// Required literal union: each branch contributes its most
		// selective required set.
		best := bestLitSet(sf)
		if best == nil || (unionFoldSet && best.fold != unionFold) {
			litsOK = false
		} else {
			union = append(union, best.lits...)
			unionFold, unionFoldSet = best.fold, true
		}
		// Required run union: weakest branch bound over the union class.
		if br := bestRun(sf); br == nil {
			minRun = 0
		} else {
			for c, ok := range br.class {
				if ok {
					runClass[c] = true
				}
			}
			if minRun < 0 || br.min < minRun {
				minRun = br.min
			}
		}
	}
	if !f.exactOK {
		f.exact = nil
	}
	if litsOK && len(union) > 0 && len(union) <= maxLitSet {
		f.lits = []litSet{{lits: union, fold: unionFold}}
	}
	if minRun > 0 {
		f.runs = []byteRun{{class: runClass, min: minRun}}
	}
	return f
}

func bestLitSet(f facts) *litSet {
	var best *litSet
	score := -1
	for i := range f.lits {
		l := &f.lits[i]
		if len(l.lits) == 0 || len(l.lits) > maxLitSet || l.hasEmpty() {
			continue
		}
		short := len(l.lits[0])
		for _, x := range l.lits {
			if len(x) < short {
				short = len(x)
			}
		}
		if short > score {
			best, score = l, short
		}
	}
	return best
}

func bestRun(f facts) *byteRun {
	var best *byteRun
	for i := range f.runs {
		if best == nil || f.runs[i].min > best.min {
			best = &f.runs[i]
		}
	}
	return best
}

func stringBytes(s string) []byte { return unsafe.Slice(unsafe.StringData(s), len(s)) }
