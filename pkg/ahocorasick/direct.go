package ahocorasick

import (
	"bytes"
	"sort"
)

// trieEdge is the only sparse representation used while the direct builder
// is running. Edges are sorted by parent and byte before the BFS, then each
// node is addressed by a compact range.
type trieEdge struct {
	parent int32
	byte   byte
	child  int32
}

func newDirect(patterns [][]byte) *Matcher {
	order := make([]int, 0, len(patterns))
	var present [256]bool
	maxPatternLen := 0
	for id, pattern := range patterns {
		if len(pattern) == 0 {
			continue
		}
		order = append(order, id)
		if len(pattern) > maxPatternLen {
			maxPatternLen = len(pattern)
		}
		for _, b := range pattern {
			present[b] = true
		}
	}
	sort.Slice(order, func(i, j int) bool {
		left, right := patterns[order[i]], patterns[order[j]]
		if cmp := bytes.Compare(left, right); cmp != 0 {
			return cmp < 0
		}
		// Keep duplicate IDs in caller order. MatchHitsInto exposes that order.
		return order[i] < order[j]
	})

	stateCount := 1
	previous := -1
	for _, id := range order {
		common := 0
		if previous >= 0 {
			common = commonPrefix(patterns[previous], patterns[id])
		}
		stateCount += len(patterns[id]) - common
		previous = id
	}

	m := &Matcher{
		patternsAt:  make([][]int32, stateCount),
		numPatterns: len(patterns),
		failure:     make([]int32, stateCount),
		dictLink:    make([]int32, stateCount),
	}
	for i := range m.dictLink {
		m.dictLink[i] = -1
	}

	var alphabet [256]byte
	alphabetLen := 0
	for i, found := range present {
		if found {
			alphabet[alphabetLen] = byte(i)
			alphabetLen++
		}
	}
	if alphabetLen == len(m.symbols) {
		for i := range m.symbols {
			m.symbols[i] = uint16(i)
		}
		m.stride = alphabetLen
	} else {
		unknown := uint16(alphabetLen)
		for i := range m.symbols {
			m.symbols[i] = unknown
		}
		for i := 0; i < alphabetLen; i++ {
			m.symbols[alphabet[i]] = uint16(i)
		}
		m.stride = alphabetLen + 1
	}

	edges := make([]trieEdge, 0, stateCount-1)
	edgeStart := make([]int32, stateCount)
	edgeCount := make([]uint16, stateCount)
	path := make([]int32, 1, maxPatternLen+1)
	path[0] = 0
	previous = -1
	nextNode := int32(1)
	for _, id := range order {
		pattern := patterns[id]
		common := 0
		if previous >= 0 {
			common = commonPrefix(patterns[previous], pattern)
		}
		path = path[:common+1]
		parent := path[common]
		for i := common; i < len(pattern); i++ {
			child := nextNode
			nextNode++
			edges = append(edges, trieEdge{parent: parent, byte: pattern[i], child: child})
			edgeCount[parent]++
			path = append(path, child)
			parent = child
		}
		m.patternsAt[path[len(pattern)]] = append(m.patternsAt[path[len(pattern)]], int32(id))
		previous = id
	}
	if nextNode != int32(stateCount) {
		panic("ahocorasick: direct trie state count mismatch")
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].parent != edges[j].parent {
			return edges[i].parent < edges[j].parent
		}
		return edges[i].byte < edges[j].byte
	})
	for i, edge := range edges {
		if i == 0 || edge.parent != edges[i-1].parent {
			edgeStart[edge.parent] = int32(i)
		}
	}

	m.buildDirect(edges, edgeStart, edgeCount)
	return m
}

func commonPrefix(left, right []byte) int {
	if left == nil {
		return 0
	}
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for i := 0; i < limit; i++ {
		if left[i] != right[i] {
			return i
		}
	}
	return limit
}

func (m *Matcher) buildDirect(edges []trieEdge, edgeStart []int32, edgeCount []uint16) {
	stateCount := len(m.patternsAt)
	if stateCount <= maxNarrowStates {
		m.next16 = make([]uint16, stateCount*m.stride)
	} else {
		m.next = make([]int32, stateCount*m.stride)
	}

	queue := make([]int32, 0, stateCount)
	rootEdges := edges[:edgeCount[0]]
	for _, edge := range rootEdges {
		m.setTransition(int(m.symbols[edge.byte]), edge.child)
		queue = append(queue, edge.child)
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		failure := m.failure[node]
		row := int(node) * m.stride
		for symbol := 0; symbol < m.stride; symbol++ {
			m.setTransition(row+symbol, m.transition(failure, uint16(symbol)))
		}

		start := edgeStart[node]
		for _, edge := range edges[start : int(start)+int(edgeCount[node])] {
			symbol := m.symbols[edge.byte]
			m.setTransition(row+int(symbol), edge.child)
			childFailure := m.transition(failure, symbol)
			m.failure[edge.child] = childFailure
			if len(m.patternsAt[childFailure]) > 0 {
				m.dictLink[edge.child] = childFailure
			} else {
				m.dictLink[edge.child] = m.dictLink[childFailure]
			}
			queue = append(queue, edge.child)
		}
	}
	m.failure = nil
}

func (m *Matcher) transition(state int32, symbol uint16) int32 {
	index := int(state)*m.stride + int(symbol)
	if m.next16 != nil {
		return int32(m.next16[index])
	}
	return m.next[index]
}

func (m *Matcher) setTransition(index int, state int32) {
	if m.next16 != nil {
		m.next16[index] = uint16(state)
		return
	}
	m.next[index] = state
}
