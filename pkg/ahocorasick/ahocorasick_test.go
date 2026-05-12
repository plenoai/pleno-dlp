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

func TestMatchInto_ReusesBuffers(t *testing.T) {
	m := New([][]byte{[]byte("aaa")})
	seen := make([]bool, m.NumPatterns())
	out := make([]int32, 0, 4)
	out = m.MatchInto([]byte("xx aaa yy"), seen, out[:0])
	if len(out) != 1 || out[0] != 0 {
		t.Fatalf("first match got %v", out)
	}
	// Caller resets buffers and re-uses them.
	for i := range seen {
		seen[i] = false
	}
	out = m.MatchInto([]byte("nothing here"), seen, out[:0])
	if len(out) != 0 {
		t.Fatalf("second match: expected empty, got %v", out)
	}
}
