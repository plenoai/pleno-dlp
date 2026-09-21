// Package ahocorasick is a small in-repo Aho-Corasick multi-pattern matcher
// used by the engine as a keyword prefilter across all registered detectors.
//
// Two design choices justify rolling our own instead of pulling in a third
// party module:
//
//   - The matcher is on the engine's hot path (called once per chunk variant).
//     We need predictable allocation behaviour and a Match() API that returns
//     pattern IDs, not byte offsets — that lets the engine accumulate a
//     "which detectors fire" set with zero string materialisation.
//   - Dependency policy in CLAUDE.md is conservative; adding a transitive dep
//     for a 200-line algorithm is the wrong trade-off.
//
// The matcher is case-sensitive. Callers that need case-insensitive matching
// (the engine does) are expected to lower-case both the patterns at build
// time and the input at scan time. Doing the lowercasing here would force
// every Match() call to allocate; pushing it to the caller lets them reuse
// a pooled buffer.
package ahocorasick

// Matcher is a frozen Aho-Corasick automaton over a fixed pattern set.
// Construct once, query many times; Match is safe for concurrent use because
// the automaton is read-only after New returns.
type Matcher struct {
	// failure[i] is the longest proper suffix of the prefix that node i
	// represents that is also a prefix of some pattern. Built via BFS.
	failure []int32
	// output is the dictionary suffix link: from node i, jump to the
	// nearest ancestor (via failure chain) that is itself a pattern
	// terminal. -1 sentinel means "no further outputs along this chain".
	dictLink []int32
	// patternsAt[i] holds the IDs of patterns terminating exactly at node
	// i. Multiple IDs share a node when the same byte sequence was added
	// twice with different IDs — pleno-dlp does this when several
	// detectors share a keyword like "key" or "token".
	patternsAt  [][]int32
	numPatterns int
	// symbols maps input bytes to a compact alphabet. The final symbol is
	// reserved for bytes absent from every pattern and always returns root.
	symbols [256]uint16
	// next is the wide fallback DFA for catalogs with more than 65,536 trie
	// states. Built-in catalogs use next16 to halve the common table.
	next   []int32
	next16 []uint16
	stride int
}

const maxNarrowStates = 1 << 16

// New compiles patterns into an automaton. patterns[i] becomes pattern ID i.
// Empty patterns are ignored — they would match everywhere and aren't a
// useful signal for the engine prefilter.
func New(patterns [][]byte) *Matcher {
	return newDirect(patterns)
}

// Match walks data through the automaton and returns every pattern ID that
// appears at least once, in arbitrary order, with no duplicates. The
// returned slice is freshly allocated; callers that scan many chunks should
// consider MatchInto when they own a reusable buffer.
func (m *Matcher) Match(data []byte) []int32 {
	if len(data) == 0 {
		return nil
	}
	seen := make([]bool, m.numPatterns)
	var out []int32
	m.walk(data, seen, &out)
	return out
}

// MatchInto is the allocation-conscious variant. seen must have length >=
// number of patterns indexed (i.e. at least max(pattern IDs)+1). Callers
// MUST clear seen between calls; the matcher does not, so a re-used slice
// from a sync.Pool stays cheap to reset (range + zero).
//
// Returned IDs are appended to out and the (possibly grown) slice is
// returned. Pass nil for out to let MatchInto allocate.
func (m *Matcher) MatchInto(data []byte, seen []bool, out []int32) []int32 {
	if len(data) == 0 {
		return out
	}
	m.walk(data, seen, &out)
	return out
}

func (m *Matcher) walk(data []byte, seen []bool, out *[]int32) {
	state := int32(0)
	for _, b := range data {
		state = m.transition(state, m.symbols[b])
		// Emit terminals at the current node, then walk the dictionary
		// suffix chain to emit any shorter pattern matches that overlap.
		for s := state; s > 0; {
			for _, id := range m.patternsAt[s] {
				if int(id) < len(seen) && !seen[id] {
					seen[id] = true
					*out = append(*out, id)
				}
			}
			s = m.dictLink[s]
			if s < 0 {
				break
			}
		}
	}
}

// Hit pairs a matched pattern with the offset of the byte that
// completed it (i.e. the last byte of the keyword in `data`). Callers
// can subtract the keyword length to recover the start, or treat the
// hit as a midpoint when sizing a vicinity window.
type Hit struct {
	PatternID int32
	End       int
}

// MatchHitsInto walks data and appends one Hit per pattern occurrence —
// duplicates included. Unlike Match it does not de-dup; that lets the
// engine cluster keywords by detector and slice tight vicinity windows
// per cluster instead of running every dispatched detector against the
// whole chunk.
//
// out is appended to; the (possibly grown) slice is returned. Pass nil
// to let MatchHitsInto allocate.
func (m *Matcher) MatchHitsInto(data []byte, out []Hit) []Hit {
	m.VisitHits(data, func(hit Hit) {
		out = append(out, hit)
	})
	return out
}

// VisitHits walks data in input order and calls visit for every pattern
// occurrence. It avoids retaining the complete hit list when callers can
// consume matches immediately.
func (m *Matcher) VisitHits(data []byte, visit func(Hit)) {
	state := int32(0)
	for i, b := range data {
		state = m.transition(state, m.symbols[b])
		for s := state; s > 0; {
			for _, id := range m.patternsAt[s] {
				visit(Hit{PatternID: id, End: i})
			}
			s = m.dictLink[s]
			if s < 0 {
				break
			}
		}
	}
}

// NumPatterns reports the upper bound on pattern IDs the matcher will emit.
// Callers sizing reusable `seen` buffers should use this rather than
// `len(patterns)`, which can differ if patterns are skipped or IDs reused.
func (m *Matcher) NumPatterns() int { return m.numPatterns }
