package archive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
)

func readJoined(t *testing.T, r io.ReaderAt, size int64) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := r.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func vols(parts ...[]byte) []Volume {
	out := make([]Volume, len(parts))
	for i, p := range parts {
		out[i] = Volume{R: bytes.NewReader(p), Size: int64(len(p))}
	}
	return out
}

func TestParseVolumeName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scheme  VolumeScheme
		index   int
		sibling string
	}{
		{"backup.vol1.egg", VolumeEgg, 1, "backup.vol3.egg"},
		{"dir/Backup.VOL12.EGG", VolumeEgg, 12, "dir/Backup.VOL3.EGG"},
		{"data.zip.001", VolumeBytes, 1, "data.zip.003"},
		{"logs.tar.gz.010", VolumeBytes, 10, "logs.tar.gz.003"},
	} {
		id, ok := ParseVolumeName(tc.name)
		if !ok || id.Scheme != tc.scheme || id.Index != tc.index {
			t.Fatalf("%s: got %+v %v", tc.name, id, ok)
		}
		if got := id.Sibling(3); got != tc.sibling {
			t.Fatalf("%s: sibling %q want %q", tc.name, got, tc.sibling)
		}
	}
	for _, name := range []string{"a.egg", "a.vol0.egg", "a.zip.000", "a.txt.001", "a.7z.001", "a.zip"} {
		if _, ok := ParseVolumeName(name); ok {
			t.Fatalf("%s: unexpected volume", name)
		}
	}
}

func TestJoinVolumesBytesZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("deep/secret.txt")
	_, _ = w.Write([]byte("FIXTURE-ZIP-ACROSS-VOLUMES"))
	_ = zw.Close()
	b := buf.Bytes()
	third := len(b) / 3
	r, size, n, err := JoinVolumes(VolumeBytes, vols(b[:third], b[third:2*third], b[2*third:]), 1<<20)
	if err != nil || n != 3 || size != int64(len(b)) {
		t.Fatalf("join: n=%d size=%d err=%v", n, size, err)
	}
	entries, err := walkEntries(t, "data.zip.001", readJoined(t, r, size), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	requireEntry(t, entries, "data.zip.001!deep/secret.txt", "FIXTURE-ZIP-ACROSS-VOLUMES")
	if _, _, _, err := JoinVolumes(VolumeBytes, vols(b[:third], b[third:]), int64(len(b)-1)); !errors.Is(err, ErrVolumeChain) {
		t.Fatalf("budget: want ErrVolumeChain, got %v", err)
	}
}

func splitEggFixture(t *testing.T, method byte) ([][]byte, []byte) {
	rng := rand.New(rand.NewPCG(3, 4))
	filler := make([]byte, 4096)
	for i := range filler {
		filler[i] = 'a' + byte(rng.IntN(26))
	}
	plain := []byte("FIXTURE-SPLIT-PREFIX " + string(filler) + " TAIL-IN-SECOND-VOLUME")
	body := buildEgg(t, nil, []eggTestFile{
		{name: "whole.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-WHOLE-MEMBER")}}},
		{name: "cut.txt", blocks: []eggTestBlock{{method: method, plain: plain}}},
		{name: "after.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-AFTER-CUT")}}},
	})
	at := bytes.Index(body, []byte("cut.txt"))
	blk := bytes.Index(body[at:], le32(eggBlockMagic)) + at
	csize := int(binary.LittleEndian.Uint32(body[blk+10:]))
	return splitVolumes(body, blk+22+csize/2), plain
}

func TestJoinVolumesEggDecodesAcrossBoundary(t *testing.T) {
	for _, method := range []byte{eggMethodStore, eggMethodDeflate, eggMethodLZMA} {
		parts, plain := splitEggFixture(t, method)
		r, size, n, err := JoinVolumes(VolumeEgg, vols(parts...), 1<<20)
		if err != nil || n != 2 {
			t.Fatalf("method %d: n=%d err=%v", method, n, err)
		}
		entries, err := walkEntries(t, "a.vol1.egg", readJoined(t, r, size), Limits{})
		if err != nil {
			t.Fatalf("method %d: joined split archive must have no gaps, got %v", method, err)
		}
		if got := entries["a.vol1.egg!cut.txt"]; got != string(plain) {
			t.Fatalf("method %d: cut member not fully decoded (%d of %d bytes)", method, len(got), len(plain))
		}
		requireEntry(t, entries, "a.vol1.egg!whole.txt", "FIXTURE-WHOLE-MEMBER")
		requireEntry(t, entries, "a.vol1.egg!after.txt", "FIXTURE-AFTER-CUT")
	}
}

func TestJoinVolumesEggChain(t *testing.T) {
	parts, _ := splitEggFixture(t, eggMethodStore)
	// An unrelated continuation (prev id does not link) is not spliced in.
	other := append([]byte{}, parts[1]...)
	at := bytes.Index(other, le32(eggSplitMagic)) + 7
	binary.LittleEndian.PutUint32(other[at:], 999)
	if _, _, n, err := JoinVolumes(VolumeEgg, vols(parts[0], other), 1<<20); err != nil || n != 1 {
		t.Fatalf("broken chain: n=%d err=%v", n, err)
	}
	// A continuation volume cannot head a set.
	if _, _, _, err := JoinVolumes(VolumeEgg, vols(parts[1], parts[0]), 1<<20); !errors.Is(err, ErrVolumeChain) {
		t.Fatalf("reversed: want ErrVolumeChain, got %v", err)
	}
	// A missing tail leaves the split-volume gap in place.
	half := parts[1][:len(parts[1])/2]
	r, size, _, err := JoinVolumes(VolumeEgg, vols(parts[0], half), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walkEntries(t, "a.vol1.egg", readJoined(t, r, size), Limits{}); !partialKinds(err)["split-volume"] && !partialKinds(err)["corrupt-archive"] {
		t.Fatalf("truncated tail: want a gap, got %v", err)
	}
}

func FuzzJoinVolumesEgg(f *testing.F) {
	f.Add([]byte("EGGA"), []byte("EGGA"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		r, size, _, err := JoinVolumes(VolumeEgg, vols(a, b), 1<<20)
		if err != nil {
			return
		}
		buf := make([]byte, size)
		if _, err := r.ReadAt(buf, 0); err != nil {
			t.Fatal(err)
		}
		_, _ = Walk("a.vol1.egg", buf, Limits{})
	})
}
