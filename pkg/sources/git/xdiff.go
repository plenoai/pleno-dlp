package git

import (
	"bytes"
	"encoding/binary"
	"hash/maphash"
	"math/bits"
	"strconv"
)

// This file is a line-for-line port of the parts of git's xdiff (v2.56.0,
// xdiff/xprepare.c, xdiffi.c, xemit.c) that `git log -p` exercises with the
// options nativeLogArgs passes: --diff-algorithm=myers (no XDF_NEED_MINIMAL),
// --no-indent-heuristic, --unified=3, --inter-hunk-context=0, no whitespace
// or blank-line ignoring, and the default (no diff driver) function-name
// matcher for hunk headers. The in-process blob differ (#983) must render
// byte-identical hunks to git, because added-line attribution, the scanned
// hunk windows, and the Line-means-Data[0] contract all derive from them;
// TestXDiffMatchesGit and the corpus parity check pin that equivalence.
// Keep the control flow aligned with the C source when editing.

const (
	xdlMaxEqLimit     = 1024
	xdlSimscanWindow  = 100
	xdlKpdisRun       = 4
	xdlMaxCostMin     = 256
	xdlHeurMinCost    = 256
	xdlSnakeCnt       = 20
	xdlKHeur          = 4
	xdlLineMax        = int(^uint(0) >> 1)
	xdlContextLen     = 3
	xdlInterHunkCtx   = 0
	xdlFuncLineBuffer = 80

	xdlDiscard     = 0
	xdlKeep        = 1
	xdlInvestigate = 2
)

type xdFile struct {
	recs [][]byte // records, each including its trailing '\n' when present
	mph  []int32  // equivalence class per record
	// changed has one sentinel slot on each side: changed[i+1] is record i.
	changed []bool
	ref     []int32 // reference_index: records that take part in the diff
	dstart  int
	dend    int
}

func (f *xdFile) isChanged(i int) bool {
	i++
	return i >= 0 && i < len(f.changed) && f.changed[i]
}

func (f *xdFile) setChanged(i int, v bool) { f.changed[i+1] = v }

func (f *xdFile) hash(index int) int32 { return f.mph[f.ref[index]] }

type xdChange struct {
	i1, i2     int
	chg1, chg2 int
}

// xdiffer holds reusable scratch state; it is not safe for concurrent use.
type xdiffer struct {
	classes xdClassTable
	len1    []int32
	len2    []int32
	f1, f2  xdFile
	kvd     []int
	action1 []byte
	action2 []byte
	changes []xdChange
}

func xdlBogosqrt(n uint64) int {
	i := uint64(1)
	for ; n > 0; n >>= 2 {
		i <<= 1
	}
	return int(i)
}

// xdlSplitRecords splits data into newline-terminated records; a final
// record without a newline is kept. Newlines are located eight bytes per
// load: source lines are short, so a per-line bytes.IndexByte call costs
// more in setup than in scanning.
func xdlSplitRecords(data []byte, recs [][]byte) [][]byte {
	recs = recs[:0]
	const low7, hi, nl = 0x7f7f7f7f7f7f7f7f, 0x8080808080808080, 0x0a0a0a0a0a0a0a0a
	start, i := 0, 0
	for ; i+8 <= len(data); i += 8 {
		w := binary.LittleEndian.Uint64(data[i:]) ^ nl
		// High bit set exactly in the zero bytes of w (the newlines).
		m := ^(((w & low7) + low7) | w) & hi
		for m != 0 {
			k := i + bits.TrailingZeros64(m)>>3
			recs = append(recs, data[start:k+1])
			start = k + 1
			m &= m - 1
		}
	}
	for ; i < len(data); i++ {
		if data[i] == '\n' {
			recs = append(recs, data[start:i+1])
			start = i + 1
		}
	}
	if start < len(data) {
		recs = append(recs, data[start:])
	}
	return recs
}

func (x *xdiffer) prepare(a, b []byte) {
	x.len1, x.len2 = x.len1[:0], x.len2[:0]
	x.f1.recs = xdlSplitRecords(a, x.f1.recs)
	x.f2.recs = xdlSplitRecords(b, x.f2.recs)
	x.classes.reset(len(x.f1.recs) + len(x.f2.recs))
	x.f1.mph = x.classify(1, x.f1.recs, x.f1.mph)
	x.f2.mph = x.classify(2, x.f2.recs, x.f2.mph)
	for _, f := range []*xdFile{&x.f1, &x.f2} {
		n := len(f.recs) + 2
		if cap(f.changed) < n {
			f.changed = make([]bool, n)
		} else {
			f.changed = f.changed[:n]
			clear(f.changed)
		}
		f.ref = f.ref[:0]
		f.dstart = 0
		f.dend = len(f.recs) - 1
	}
	x.trimEnds()
	x.cleanupRecords()
}

func (x *xdiffer) classify(pass int, recs [][]byte, mph []int32) []int32 {
	mph = mph[:0]
	for _, rec := range recs {
		id, added := x.classes.lookup(rec)
		if added {
			x.len1 = append(x.len1, 0)
			x.len2 = append(x.len2, 0)
		}
		if pass == 1 {
			x.len1[id]++
		} else {
			x.len2[id]++
		}
		mph = append(mph, id)
	}
	return mph
}

func (x *xdiffer) trimEnds() {
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

func xdlCleanMmatch(action []byte, i, length int) bool {
	s, e := 0, length-1
	if i-s > xdlSimscanWindow {
		s = i - xdlSimscanWindow
	}
	if e-i > xdlSimscanWindow {
		e = i + xdlSimscanWindow
	}
	rdis0, rpdis0 := 0, 1
	for r := 1; i-r >= s; r++ {
		switch action[i-r] {
		case xdlDiscard:
			rdis0++
			continue
		case xdlInvestigate:
			rpdis0++
			continue
		}
		break
	}
	if rdis0 == 0 {
		return false
	}
	rdis1, rpdis1 := 0, 1
	for r := 1; i+r <= e; r++ {
		switch action[i+r] {
		case xdlDiscard:
			rdis1++
			continue
		case xdlInvestigate:
			rpdis1++
			continue
		}
		break
	}
	if rdis1 == 0 {
		return false
	}
	rdis1 += rdis0
	rpdis1 += rpdis0
	return rpdis1*xdlKpdisRun < rpdis1+rdis1
}

func (x *xdiffer) cleanupRecords() {
	f1, f2 := &x.f1, &x.f2
	off := f1.dstart
	len1 := f1.dend - off + 1
	len2 := f2.dend - off + 1
	x.action1 = growBytes(x.action1, len1)
	x.action2 = growBytes(x.action2, len2)
	mlim1 := min(xdlBogosqrt(uint64(len(f1.recs))), xdlMaxEqLimit)
	for i := 0; i < len1; i++ {
		nm := int(x.len2[f1.mph[i+off]])
		switch {
		case nm == 0:
			x.action1[i] = xdlDiscard
		case nm < mlim1:
			x.action1[i] = xdlKeep
		default:
			x.action1[i] = xdlInvestigate
		}
	}
	mlim2 := min(xdlBogosqrt(uint64(len(f2.recs))), xdlMaxEqLimit)
	for i := 0; i < len2; i++ {
		nm := int(x.len1[f2.mph[i+off]])
		switch {
		case nm == 0:
			x.action2[i] = xdlDiscard
		case nm < mlim2:
			x.action2[i] = xdlKeep
		default:
			x.action2[i] = xdlInvestigate
		}
	}
	cleanup := func(f *xdFile, action []byte, n int) {
		for i := 0; i < n; i++ {
			a := action[i]
			if a == xdlInvestigate {
				if xdlCleanMmatch(action, i, n) {
					a = xdlDiscard
				} else {
					a = xdlKeep
				}
			}
			if a == xdlKeep {
				f.ref = append(f.ref, int32(i+off))
			} else {
				f.setChanged(i+off, true)
			}
		}
	}
	cleanup(f1, x.action1, len1)
	cleanup(f2, x.action2, len2)
}

func growBytes(b []byte, n int) []byte {
	if n < 0 {
		n = 0
	}
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

type xdSplit struct {
	i1, i2       int
	minLo, minHi bool
}

type xdAlgoEnv struct {
	mxcost, snakeCnt, heurMin int
}

// kv indexes a K vector whose diagonal 0 sits at base.
type xdKV struct {
	v    []int
	base int
}

func (k xdKV) get(d int) int      { return k.v[k.base+d] }
func (k xdKV) set(d int, val int) { k.v[k.base+d] = val }

func xdlSplitBox(f1 *xdFile, off1, lim1 int, f2 *xdFile, off2, lim2 int, kvdf, kvdb xdKV, needMin bool, spl *xdSplit, env *xdAlgoEnv) {
	dmin, dmax := off1-lim2, lim1-off2
	fmid, bmid := off1-off2, lim1-lim2
	odd := (fmid - bmid) & 1
	fmin, fmax := fmid, fmid
	bmin, bmax := bmid, bmid

	kvdf.set(fmid, off1)
	kvdb.set(bmid, lim1)

	for ec := 1; ; ec++ {
		gotSnake := false

		if fmin > dmin {
			fmin--
			kvdf.set(fmin-1, -1)
		} else {
			fmin++
		}
		if fmax < dmax {
			fmax++
			kvdf.set(fmax+1, -1)
		} else {
			fmax--
		}

		for d := fmax; d >= fmin; d -= 2 {
			var i1 int
			if kvdf.get(d-1) >= kvdf.get(d+1) {
				i1 = kvdf.get(d-1) + 1
			} else {
				i1 = kvdf.get(d + 1)
			}
			prev1 := i1
			i2 := i1 - d
			for i1 < lim1 && i2 < lim2 && f1.hash(i1) == f2.hash(i2) {
				i1++
				i2++
			}
			if i1-prev1 > env.snakeCnt {
				gotSnake = true
			}
			kvdf.set(d, i1)
			if odd != 0 && bmin <= d && d <= bmax && kvdb.get(d) <= i1 {
				spl.i1, spl.i2 = i1, i2
				spl.minLo, spl.minHi = true, true
				return
			}
		}

		if bmin > dmin {
			bmin--
			kvdb.set(bmin-1, xdlLineMax)
		} else {
			bmin++
		}
		if bmax < dmax {
			bmax++
			kvdb.set(bmax+1, xdlLineMax)
		} else {
			bmax--
		}

		for d := bmax; d >= bmin; d -= 2 {
			var i1 int
			if kvdb.get(d-1) < kvdb.get(d+1) {
				i1 = kvdb.get(d - 1)
			} else {
				i1 = kvdb.get(d+1) - 1
			}
			prev1 := i1
			i2 := i1 - d
			for i1 > off1 && i2 > off2 && f1.hash(i1-1) == f2.hash(i2-1) {
				i1--
				i2--
			}
			if prev1-i1 > env.snakeCnt {
				gotSnake = true
			}
			kvdb.set(d, i1)
			if odd == 0 && fmin <= d && d <= fmax && i1 <= kvdf.get(d) {
				spl.i1, spl.i2 = i1, i2
				spl.minLo, spl.minHi = true, true
				return
			}
		}

		if needMin {
			continue
		}

		if gotSnake && ec > env.heurMin {
			best := 0
			for d := fmax; d >= fmin; d -= 2 {
				dd := fmid - d
				if d > fmid {
					dd = d - fmid
				}
				i1 := kvdf.get(d)
				i2 := i1 - d
				v := (i1 - off1) + (i2 - off2) - dd
				if v > xdlKHeur*ec && v > best &&
					off1+env.snakeCnt <= i1 && i1 < lim1 &&
					off2+env.snakeCnt <= i2 && i2 < lim2 {
					for k := 1; f1.hash(i1-k) == f2.hash(i2-k); k++ {
						if k == env.snakeCnt {
							best = v
							spl.i1, spl.i2 = i1, i2
							break
						}
					}
				}
			}
			if best > 0 {
				spl.minLo, spl.minHi = true, false
				return
			}

			best = 0
			for d := bmax; d >= bmin; d -= 2 {
				dd := bmid - d
				if d > bmid {
					dd = d - bmid
				}
				i1 := kvdb.get(d)
				i2 := i1 - d
				v := (lim1 - i1) + (lim2 - i2) - dd
				if v > xdlKHeur*ec && v > best &&
					off1 < i1 && i1 <= lim1-env.snakeCnt &&
					off2 < i2 && i2 <= lim2-env.snakeCnt {
					for k := 0; f1.hash(i1+k) == f2.hash(i2+k); k++ {
						if k == env.snakeCnt-1 {
							best = v
							spl.i1, spl.i2 = i1, i2
							break
						}
					}
				}
			}
			if best > 0 {
				spl.minLo, spl.minHi = false, true
				return
			}
		}

		if ec >= env.mxcost {
			fbest, fbest1 := -1, -1
			for d := fmax; d >= fmin; d -= 2 {
				i1 := min(kvdf.get(d), lim1)
				i2 := i1 - d
				if lim2 < i2 {
					i1 = lim2 + d
					i2 = lim2
				}
				if fbest < i1+i2 {
					fbest = i1 + i2
					fbest1 = i1
				}
			}
			bbest, bbest1 := xdlLineMax, xdlLineMax
			for d := bmax; d >= bmin; d -= 2 {
				i1 := max(off1, kvdb.get(d))
				i2 := i1 - d
				if i2 < off2 {
					i1 = off2 + d
					i2 = off2
				}
				if i1+i2 < bbest {
					bbest = i1 + i2
					bbest1 = i1
				}
			}
			if (lim1+lim2)-bbest < fbest-(off1+off2) {
				spl.i1, spl.i2 = fbest1, fbest-fbest1
				spl.minLo, spl.minHi = true, false
			} else {
				spl.i1, spl.i2 = bbest1, bbest-bbest1
				spl.minLo, spl.minHi = false, true
			}
			return
		}
	}
}

func xdlRecsCmp(f1 *xdFile, off1, lim1 int, f2 *xdFile, off2, lim2 int, kvdf, kvdb xdKV, needMin bool, env *xdAlgoEnv) {
	for off1 < lim1 && off2 < lim2 && f1.hash(off1) == f2.hash(off2) {
		off1++
		off2++
	}
	for off1 < lim1 && off2 < lim2 && f1.hash(lim1-1) == f2.hash(lim2-1) {
		lim1--
		lim2--
	}
	switch {
	case off1 == lim1:
		for ; off2 < lim2; off2++ {
			f2.setChanged(int(f2.ref[off2]), true)
		}
	case off2 == lim2:
		for ; off1 < lim1; off1++ {
			f1.setChanged(int(f1.ref[off1]), true)
		}
	default:
		var spl xdSplit
		xdlSplitBox(f1, off1, lim1, f2, off2, lim2, kvdf, kvdb, needMin, &spl, env)
		xdlRecsCmp(f1, off1, spl.i1, f2, off2, spl.i2, kvdf, kvdb, spl.minLo, env)
		xdlRecsCmp(f1, spl.i1, lim1, f2, spl.i2, lim2, kvdf, kvdb, spl.minHi, env)
	}
}

func (x *xdiffer) doDiff(a, b []byte) {
	x.prepare(a, b)
	n1, n2 := len(x.f1.ref), len(x.f2.ref)
	ndiags := n1 + n2 + 3
	need := 2*ndiags + 2
	if cap(x.kvd) < need {
		x.kvd = make([]int, need)
	} else {
		x.kvd = x.kvd[:need]
	}
	kvdf := xdKV{v: x.kvd, base: n2 + 1}
	kvdb := xdKV{v: x.kvd, base: ndiags + n2 + 1}
	env := xdAlgoEnv{
		mxcost:   max(xdlBogosqrt(uint64(ndiags)), xdlMaxCostMin),
		snakeCnt: xdlSnakeCnt,
		heurMin:  xdlHeurMinCost,
	}
	xdlRecsCmp(&x.f1, 0, n1, &x.f2, 0, n2, kvdf, kvdb, false, &env)
}

type xdGroup struct{ start, end int }

func (f *xdFile) groupInit(g *xdGroup) {
	g.start, g.end = 0, 0
	for f.isChanged(g.end) {
		g.end++
	}
}

func (f *xdFile) groupNext(g *xdGroup) bool {
	if g.end == len(f.recs) {
		return false
	}
	g.start = g.end + 1
	for g.end = g.start; f.isChanged(g.end); g.end++ {
	}
	return true
}

func (f *xdFile) groupPrevious(g *xdGroup) bool {
	if g.start == 0 {
		return false
	}
	g.end = g.start - 1
	for g.start = g.end; f.isChanged(g.start - 1); g.start-- {
	}
	return true
}

func (f *xdFile) groupSlideDown(g *xdGroup) bool {
	if g.end < len(f.recs) && f.mph[g.start] == f.mph[g.end] {
		f.setChanged(g.start, false)
		g.start++
		f.setChanged(g.end, true)
		g.end++
		for f.isChanged(g.end) {
			g.end++
		}
		return true
	}
	return false
}

func (f *xdFile) groupSlideUp(g *xdGroup) bool {
	if g.start > 0 && f.mph[g.start-1] == f.mph[g.end-1] {
		g.start--
		f.setChanged(g.start, true)
		g.end--
		f.setChanged(g.end, false)
		for f.isChanged(g.start - 1) {
			g.start--
		}
		return true
	}
	return false
}

// xdlChangeCompact ports xdl_change_compact without the indent heuristic.
// The C source BUG()s on group desynchronization; those states are
// unreachable for a consistent diff, so the port ignores the results.
func xdlChangeCompact(f, fo *xdFile) {
	var g, gOther xdGroup
	f.groupInit(&g)
	fo.groupInit(&gOther)
	for {
		if g.end != g.start {
			var earliestEnd, endMatchingOther, groupsize int
			for {
				groupsize = g.end - g.start
				endMatchingOther = -1
				for f.groupSlideUp(&g) {
					fo.groupPrevious(&gOther)
				}
				earliestEnd = g.end
				if gOther.end > gOther.start {
					endMatchingOther = g.end
				}
				for {
					if !f.groupSlideDown(&g) {
						break
					}
					fo.groupNext(&gOther)
					if gOther.end > gOther.start {
						endMatchingOther = g.end
					}
				}
				if groupsize == g.end-g.start {
					break
				}
			}
			if g.end != earliestEnd && endMatchingOther != -1 {
				for gOther.end == gOther.start {
					f.groupSlideUp(&g)
					fo.groupPrevious(&gOther)
				}
			}
		}
		if !f.groupNext(&g) {
			break
		}
		fo.groupNext(&gOther)
	}
}

func (x *xdiffer) buildScript() []xdChange {
	x.changes = x.changes[:0]
	f1, f2 := &x.f1, &x.f2
	for i1, i2 := len(f1.recs), len(f2.recs); i1 >= 0 || i2 >= 0; i1, i2 = i1-1, i2-1 {
		if f1.isChanged(i1-1) || f2.isChanged(i2-1) {
			l1 := i1
			for f1.isChanged(i1 - 1) {
				i1--
			}
			l2 := i2
			for f2.isChanged(i2 - 1) {
				i2--
			}
			x.changes = append(x.changes, xdChange{i1: i1, i2: i2, chg1: l1 - i1, chg2: l2 - i2})
		}
	}
	for i, j := 0, len(x.changes)-1; i < j; i, j = i+1, j-1 {
		x.changes[i], x.changes[j] = x.changes[j], x.changes[i]
	}
	return x.changes
}

func xdlIsAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func xdlIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// xdlDefaultFuncName ports def_ff: git's default hunk-header function line.
func xdlDefaultFuncName(rec []byte) ([]byte, bool) {
	if len(rec) == 0 || !(xdlIsAlpha(rec[0]) || rec[0] == '_' || rec[0] == '$') {
		return nil, false
	}
	n := min(len(rec), xdlFuncLineBuffer)
	for n > 0 && xdlIsSpace(rec[n-1]) {
		n--
	}
	return rec[:n], true
}

// unified appends git's unified hunks for a -> b to out and reports
// whether any hunk was emitted.
func (x *xdiffer) unified(out []byte, a, b []byte) ([]byte, bool) {
	x.doDiff(a, b)
	xdlChangeCompact(&x.f1, &x.f2)
	xdlChangeCompact(&x.f2, &x.f1)
	changes := x.buildScript()
	if len(changes) == 0 {
		return out, false
	}
	f1, f2 := &x.f1, &x.f2
	n1, n2 := len(f1.recs), len(f2.recs)
	const maxCommon = 2*xdlContextLen + xdlInterHunkCtx
	funcPrev := -1
	var funcLine []byte
	for start := 0; start < len(changes); {
		end := start
		for end+1 < len(changes) && changes[end+1].i1-(changes[end].i1+changes[end].chg1) <= maxCommon {
			end++
		}
		xch, xche := changes[start], changes[end]
		s1 := max(xch.i1-xdlContextLen, 0)
		s2 := max(xch.i2-xdlContextLen, 0)
		lctx := min(xdlContextLen, n1-(xche.i1+xche.chg1), n2-(xche.i2+xche.chg2))
		e1 := xche.i1 + xche.chg1 + lctx
		e2 := xche.i2 + xche.chg2 + lctx

		// get_func_line(s1 - 1, funclineprev): keeps the previous match
		// when none lies between the two hunks.
		if from := s1 - 1; from != funcPrev {
			step := 1
			if from > funcPrev {
				step = -1
			}
			for l := from; l != funcPrev && l >= 0 && l < n1; l += step {
				if name, ok := xdlDefaultFuncName(f1.recs[l]); ok {
					funcLine = name
					break
				}
			}
		}
		funcPrev = s1 - 1

		hdr := len(out)
		out = append(out, "@@ -"...)
		out = xdlAppendRange(out, s1+1, e1-s1)
		out = append(out, " +"...)
		out = xdlAppendRange(out, s2+1, e2-s2)
		out = append(out, " @@"...)
		if len(funcLine) > 0 {
			out = append(out, ' ')
			out = append(out, funcLine...)
		}
		// diff.c's sane_truncate_line cuts the header at the first byte
		// that does not start a valid UTF-8 character.
		out = out[:hdr+gitUTF8Prefix(out[hdr:])]
		out = append(out, '\n')

		for ; s2 < xch.i2; s2++ {
			out = xdlAppendRecord(out, ' ', f2.recs[s2])
		}
		s1, s2 = xch.i1, xch.i2
		for k := start; ; k++ {
			c := changes[k]
			for ; s1 < c.i1 && s2 < c.i2; s1, s2 = s1+1, s2+1 {
				out = xdlAppendRecord(out, ' ', f2.recs[s2])
			}
			for s1 = c.i1; s1 < c.i1+c.chg1; s1++ {
				out = xdlAppendRecord(out, '-', f1.recs[s1])
			}
			for s2 = c.i2; s2 < c.i2+c.chg2; s2++ {
				out = xdlAppendRecord(out, '+', f2.recs[s2])
			}
			if k == end {
				break
			}
			s1 = c.i1 + c.chg1
			s2 = c.i2 + c.chg2
		}
		for s2 = xche.i2 + xche.chg2; s2 < e2; s2++ {
			out = xdlAppendRecord(out, ' ', f2.recs[s2])
		}
		start = end + 1
	}
	return out, true
}

func xdlAppendRange(out []byte, s, c int) []byte {
	if c == 0 {
		s--
	}
	out = strconv.AppendInt(out, int64(s), 10)
	if c != 1 {
		out = append(out, ',')
		out = strconv.AppendInt(out, int64(c), 10)
	}
	return out
}

func xdlAppendRecord(out []byte, prefix byte, rec []byte) []byte {
	out = append(out, prefix)
	out = append(out, rec...)
	if len(rec) > 0 && rec[len(rec)-1] != '\n' {
		out = append(out, "\n\\ No newline at end of file\n"...)
	}
	return out
}

var xdHashSeed = maphash.MakeSeed()

// xdClassTable assigns equivalence classes to records (xdl_classify_record):
// two records share a class exactly when their bytes are equal. Classes are
// numbered densely in first-seen order; only equality matters to the diff.
type xdClassTable struct {
	slots  []int32 // class id + 1; 0 marks an empty slot
	hashes []uint64
	reps   [][]byte
}

func (t *xdClassTable) reset(records int) {
	n := 16
	for n < 2*records {
		n <<= 1
	}
	if cap(t.slots) < n {
		t.slots = make([]int32, n)
	} else {
		t.slots = t.slots[:n]
		clear(t.slots)
	}
	t.hashes = t.hashes[:0]
	t.reps = t.reps[:0]
}

func (t *xdClassTable) lookup(rec []byte) (int32, bool) {
	h := maphash.Bytes(xdHashSeed, rec)
	mask := uint64(len(t.slots) - 1)
	for i := h & mask; ; i = (i + 1) & mask {
		slot := t.slots[i]
		if slot == 0 {
			id := int32(len(t.reps))
			t.slots[i] = id + 1
			t.hashes = append(t.hashes, h)
			t.reps = append(t.reps, rec)
			return id, true
		}
		id := slot - 1
		if t.hashes[id] == h && bytes.Equal(t.reps[id], rec) {
			return id, false
		}
	}
}

// gitUTF8Prefix returns the length of the longest prefix of s that git's
// pick_one_utf8_char accepts character by character.
func gitUTF8Prefix(s []byte) int {
	i := 0
	for i < len(s) {
		c := s[i]
		rem := len(s) - i
		var n int
		switch {
		case c < 0x80:
			n = 1
		case c&0xe0 == 0xc0:
			if rem < 2 || s[i+1]&0xc0 != 0x80 || c&0xfe == 0xc0 {
				return i
			}
			n = 2
		case c&0xf0 == 0xe0:
			if rem < 3 || s[i+1]&0xc0 != 0x80 || s[i+2]&0xc0 != 0x80 ||
				(c == 0xe0 && s[i+1]&0xe0 == 0x80) ||
				(c == 0xed && s[i+1]&0xe0 == 0xa0) ||
				(c == 0xef && s[i+1] == 0xbf && s[i+2]&0xfe == 0xbe) {
				return i
			}
			n = 3
		case c&0xf8 == 0xf0:
			if rem < 4 || s[i+1]&0xc0 != 0x80 || s[i+2]&0xc0 != 0x80 || s[i+3]&0xc0 != 0x80 ||
				(c == 0xf0 && s[i+1]&0xf0 == 0x80) ||
				(c == 0xf4 && s[i+1] > 0x8f) || c > 0xf4 {
				return i
			}
			n = 4
		default:
			return i
		}
		i += n
	}
	return i
}
