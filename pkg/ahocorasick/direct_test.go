package ahocorasick

import (
	"bytes"
	"math/rand"
	"slices"
	"sort"
	"testing"
)

func TestDirectBuildMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed))
	for caseNo := 0; caseNo < 256; caseNo++ {
		patterns := randomPatterns(rng)
		data := make([]byte, rng.Intn(96))
		if _, err := rng.Read(data); err != nil {
			t.Fatal(err)
		}

		matcher := New(patterns)
		gotIDs := matcher.Match(data)
		slices.Sort(gotIDs)
		wantIDs := referenceIDs(patterns, data)
		slices.Sort(wantIDs)
		if !slices.Equal(gotIDs, wantIDs) {
			t.Fatalf("case %d Match=%v want %v patterns=%q data=%x", caseNo, gotIDs, wantIDs, patterns, data)
		}

		wantHits := referenceHits(patterns, data)
		if got := matcher.MatchHitsInto(data, nil); !slices.Equal(got, wantHits) {
			t.Fatalf("case %d MatchHitsInto=%v want %v patterns=%q data=%x", caseNo, got, wantHits, patterns, data)
		}
		var callbackHits []Hit
		matcher.VisitHits(data, func(hit Hit) { callbackHits = append(callbackHits, hit) })
		if !slices.Equal(callbackHits, wantHits) {
			t.Fatalf("case %d VisitHits=%v want %v", caseNo, callbackHits, wantHits)
		}
	}
}

func randomPatterns(rng *rand.Rand) [][]byte {
	patterns := make([][]byte, rng.Intn(40))
	for i := range patterns {
		patterns[i] = make([]byte, rng.Intn(10))
		if _, err := rng.Read(patterns[i]); err != nil {
			panic(err)
		}
		if i > 0 && rng.Intn(5) == 0 {
			patterns[i] = slices.Clone(patterns[rng.Intn(i)])
		}
	}
	return patterns
}

func referenceIDs(patterns [][]byte, data []byte) []int32 {
	seen := make([]bool, len(patterns))
	var ids []int32
	for end := range data {
		for id, pattern := range patterns {
			if len(pattern) == 0 || len(pattern) > end+1 || seen[id] {
				continue
			}
			if bytes.Equal(data[end+1-len(pattern):end+1], pattern) {
				seen[id] = true
				ids = append(ids, int32(id))
			}
		}
	}
	return ids
}

func referenceHits(patterns [][]byte, data []byte) []Hit {
	var hits []Hit
	for end := range data {
		ids := make([]int, 0, len(patterns))
		for id, pattern := range patterns {
			if len(pattern) != 0 && len(pattern) <= end+1 && bytes.Equal(data[end+1-len(pattern):end+1], pattern) {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool {
			left, right := ids[i], ids[j]
			if len(patterns[left]) != len(patterns[right]) {
				return len(patterns[left]) > len(patterns[right])
			}
			return left < right
		})
		for _, id := range ids {
			hits = append(hits, Hit{PatternID: int32(id), End: end})
		}
	}
	return hits
}
