package ahocorasick

import (
	"slices"
	"testing"
)

func TestMatch_BasicHits(t *testing.T) {
	m := New([][]byte{
		[]byte("he"),
		[]byte("she"),
		[]byte("his"),
		[]byte("hers"),
	})
	got := m.Match([]byte("ushers"))
	slices.Sort(got)
	want := []int32{0, 1, 3} // he, she, hers (no "his")
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestMatch_NoHit(t *testing.T) {
	m := New([][]byte{[]byte("aws_"), []byte("sk-ant-")})
	if got := m.Match([]byte("no credentials in this line")); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestMatch_SharedKeyword(t *testing.T) {
	// Two detectors that share the same keyword should each register as a
	// distinct hit so the engine dispatches both.
	m := New([][]byte{[]byte("key"), []byte("key")})
	got := m.Match([]byte("the api key is here"))
	if len(got) != 2 {
		t.Fatalf("expected both IDs to fire, got %v", got)
	}
}

func TestMatch_EmptyPatternSkipped(t *testing.T) {
	// Empty patterns are dropped — they would match at every position and
	// defeat the prefilter.
	m := New([][]byte{[]byte(""), []byte("token")})
	got := m.Match([]byte("token-foo"))
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("got %v want [1]", got)
	}
}

func TestMatch_OverlappingTerminals(t *testing.T) {
	// "ab" terminates inside "cabd"; "abd" terminates at the next position.
	// Both should fire. Without dictionary-suffix links "ab" would be
	// silently dropped.
	m := New([][]byte{[]byte("ab"), []byte("abd")})
	got := m.Match([]byte("xcabdy"))
	slices.Sort(got)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("got %v want [0 1]", got)
	}
}

func TestMatchHitsInto(t *testing.T) {
	// MatchHitsInto drives every detector's vicinity window via Hit.End, so
	// the (PatternID, End) pairs must be exact. End is the index of the last
	// byte of the match. Unlike Match, hits are NOT de-duplicated.

	// (1) A single pattern at a known offset pins End to the last-byte index.
	// "cab" in "xcaby": x=0 c=1 a=2 b=3 y=4 -> match completes at b, End=3.
	t.Run("single pattern pins End to last byte", func(t *testing.T) {
		m := New([][]byte{[]byte("cab")})
		got := m.MatchHitsInto([]byte("xcaby"), nil)
		want := []Hit{{PatternID: 0, End: 3}}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	// (2) Overlapping terminals "ab"/"abd" over "xcabdy": x=0 c=1 a=2 b=3 d=4
	// y=5. "ab" (ID 0) ends at b -> End=3; "abd" (ID 1) ends at d -> End=4.
	// The two End values differ by 1.
	t.Run("overlapping terminals End values differ by one", func(t *testing.T) {
		m := New([][]byte{[]byte("ab"), []byte("abd")})
		got := m.MatchHitsInto([]byte("xcabdy"), nil)
		var ab, abd *Hit
		for i := range got {
			switch got[i].PatternID {
			case 0:
				ab = &got[i]
			case 1:
				abd = &got[i]
			}
		}
		if ab == nil || abd == nil {
			t.Fatalf("expected both patterns to hit, got %v", got)
		}
		if ab.End != 3 {
			t.Fatalf(`"ab" End=%d want 3 (%v)`, ab.End, got)
		}
		if abd.End != 4 {
			t.Fatalf(`"abd" End=%d want 4 (%v)`, abd.End, got)
		}
		if abd.End-ab.End != 1 {
			t.Fatalf("End values should differ by 1, got %d and %d", ab.End, abd.End)
		}
	})

	// (3) Duplicate keyword "key"/"key" (two detectors sharing a keyword)
	// yields two Hits at the SAME End — no de-dup. "key" in "a key": End=4.
	t.Run("duplicate keyword two hits same End", func(t *testing.T) {
		m := New([][]byte{[]byte("key"), []byte("key")})
		got := m.MatchHitsInto([]byte("a key"), nil)
		want := []Hit{{PatternID: 0, End: 4}, {PatternID: 1, End: 4}}
		// Terminals at one node are emitted in patternsAt order (insert
		// order), so IDs 0 then 1 at the same End.
		if !slices.Equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	// (4) The same pattern occurring twice in the input yields two distinct
	// Hits at distinct End offsets. "key key": k=0 e=1 y=2 ' '=3 k=4 e=5 y=6.
	// First ends at End=2, second at End=6.
	t.Run("repeated pattern two hits distinct End", func(t *testing.T) {
		m := New([][]byte{[]byte("key")})
		got := m.MatchHitsInto([]byte("key key"), nil)
		want := []Hit{{PatternID: 0, End: 2}, {PatternID: 0, End: 6}}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	// (5) Dictionary-suffix link: "he" is a proper SUFFIX of "she", so when
	// "she" completes, "he" fires at the SAME End only via the dictLink
	// suffix-walk — not the goto path (cf. case 2's "ab"/"abd", which is a
	// prefix and fires on the main traversal). "xshey": s=1 h=2 e=3, both end
	// at 3. A mutation dropping the dictLink walk in MatchHitsInto silently
	// loses the "he" hit and is caught here.
	t.Run("dictionary-suffix link fires shorter suffix at same End", func(t *testing.T) {
		m := New([][]byte{[]byte("she"), []byte("he")})
		got := m.MatchHitsInto([]byte("xshey"), nil)
		want := []Hit{{PatternID: 0, End: 3}, {PatternID: 1, End: 3}}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v want %v (dictLink suffix-walk dropped?)", got, want)
		}
	})
}

func TestMatchInto_ReusesBuffers(t *testing.T) {
	m := New([][]byte{[]byte("aaa")})
	seen := make([]bool, m.NumPatterns())
	out := make([]int32, 0, 4)
	out = m.MatchInto([]byte("xx aaa yy"), seen, out[:0])
	if len(out) != 1 || out[0] != 0 {
		t.Fatalf("first match got %v", out)
	}
	for i := range seen {
		seen[i] = false
	}
	out = m.MatchInto([]byte("nothing here"), seen, out[:0])
	if len(out) != 0 {
		t.Fatalf("second match: expected empty, got %v", out)
	}
}
