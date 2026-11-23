package git

import (
	"bytes"
	"math/rand"
	"testing"
)

func naiveSplitRecords(data []byte) [][]byte {
	var recs [][]byte
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			return append(recs, data)
		}
		recs = append(recs, data[:nl+1])
		data = data[nl+1:]
	}
	return recs
}

// TestXdlSplitRecordsMatchesIndexByte pins the word-at-a-time splitter to
// the per-line definition, including bytes next to newlines that a
// borrow-propagating zero-byte test would misreport (0x0b, 0x8a).
func TestXdlSplitRecordsMatchesIndexByte(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	alphabet := []byte{'\n', '\n', 'a', 0x0b, 0x8a, 0x00, 0x0a ^ 0x80, 0x01, 0xff}
	for iter := 0; iter < 20000; iter++ {
		b := make([]byte, rng.Intn(70))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		got := xdlSplitRecords(b, nil)
		want := naiveSplitRecords(b)
		if len(got) != len(want) {
			t.Fatalf("%q: %d records, want %d", b, len(got), len(want))
		}
		for i := range got {
			if !bytes.Equal(got[i], want[i]) || &got[i][0] != &want[i][0] {
				t.Fatalf("%q: record %d = %q, want %q", b, i, got[i], want[i])
			}
		}
	}
}
