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
	// goto map per node, keyed by byte. A map keeps memory proportional to
	// branching factor; with detector keywords averaging ~8 ASCII chars and
	// branching being highly biased toward a handful of letters, a sparse
	// map handily beats a full 256-slot array per node.
	transitions []map[byte]int32
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
	patternsAt [][]int32
}

// New compiles patterns into an automaton. patterns[i] becomes pattern ID i.
// Empty patterns are ignored — they would match everywhere and aren't a
// useful signal for the engine prefilter.
func New(patterns [][]byte) *Matcher {
	m := &Matcher{
		transitions: []map[byte]int32{{}},
		failure:     []int32{0},
		dictLink:    []int32{-1},
		patternsAt:  [][]int32{nil},
	}
	for id, p := range patterns {
		if len(p) == 0 {
			continue
		}
		m.insert(p, int32(id))
	}
	m.buildFailure()
	return m
}

func (m *Matcher) insert(p []byte, id int32) {
	node := int32(0)
	for _, b := range p {
		next, ok := m.transitions[node][b]
		if !ok {
			next = int32(len(m.transitions))
			m.transitions = append(m.transitions, map[byte]int32{})
			m.failure = append(m.failure, 0)
			m.dictLink = append(m.dictLink, -1)
			m.patternsAt = append(m.patternsAt, nil)
			m.transitions[node][b] = next
		}
		node = next
	}
	m.patternsAt[node] = append(m.patternsAt[node], id)
}

// buildFailure populates failure links and dictionary-suffix links via
// breadth-first traversal of the trie. Root's children fail to root; deeper
// nodes follow the standard AC recurrence.
func (m *Matcher) buildFailure() {
	queue := make([]int32, 0, len(m.transitions))
	for _, child := range m.transitions[0] {
		m.failure[child] = 0
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for b, child := range m.transitions[node] {
			queue = append(queue, child)
			fail := m.failure[node]
			for fail != 0 {
				if _, ok := m.transitions[fail][b]; ok {
					break
				}
				fail = m.failure[fail]
			}
			if next, ok := m.transitions[fail][b]; ok && next != child {
				m.failure[child] = next
			} else {
				m.failure[child] = 0
			}
			// Dictionary-suffix link: the nearest failure-chain ancestor
			// that is itself a pattern terminal. Pre-computing skips
			// redundant chain walks at match time.
			f := m.failure[child]
			if len(m.patternsAt[f]) > 0 {
				m.dictLink[child] = f
			} else {
				m.dictLink[child] = m.dictLink[f]
			}
		}
	}
}

// Match walks data through the automaton and returns every pattern ID that
// appears at least once, in arbitrary order, with no duplicates. The
// returned slice is freshly allocated; callers that scan many chunks should
// consider MatchInto when they own a reusable buffer.
func (m *Matcher) Match(data []byte) []int32 {
	if len(data) == 0 {
		return nil
	}
	seen := make([]bool, len(m.patternsAt))
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
		// Follow failure links until a goto on b exists, or we land at root.
		for {
			if next, ok := m.transitions[state][b]; ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.failure[state]
		}
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
	state := int32(0)
	for i, b := range data {
		for {
			if next, ok := m.transitions[state][b]; ok {
				state = next
				break
			}
			if state == 0 {
				break
			}
			state = m.failure[state]
		}
		for s := state; s > 0; {
			for _, id := range m.patternsAt[s] {
				out = append(out, Hit{PatternID: id, End: i})
			}
			s = m.dictLink[s]
			if s < 0 {
				break
			}
		}
	}
	return out
}

// NumPatterns reports the upper bound on pattern IDs the matcher will emit.
// Callers sizing reusable `seen` buffers should use this rather than the
// original `len(patterns)` (the two differ if any empty patterns were
// skipped — they aren't, but a future caller passing duplicates with high
// IDs would care).
func (m *Matcher) NumPatterns() int { return len(m.patternsAt) }
