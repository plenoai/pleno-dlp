package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestLooksLikeArchive_DetectsKnownMagic(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"plain text", []byte("hello"), false},
		{"zip", []byte{0x50, 0x4b, 0x03, 0x04, 0x00}, true},
		{"empty zip", []byte{0x50, 0x4b, 0x05, 0x06, 0x00}, true},
		{"gzip", []byte{0x1f, 0x8b, 0x00}, true},
		// Tar requires the magic at offset 257; padding 257 zero
		// bytes followed by "ustar" satisfies it.
		{"tar", append(bytes.Repeat([]byte{0}, 257), []byte("ustar\x00")...), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeArchive(tc.data); got != tc.want {
				t.Errorf("LooksLikeArchive(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestWalk_FlatZipSurfacesEntries(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	zipBuf := buildZip(t, map[string]string{
		"config.yaml": "leak: " + akia,
		"README":      "no secrets here",
	})

	entries, err := Walk("test.zip", zipBuf, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries; got %d", len(entries))
	}
	if !containsAKIA(entries, akia) {
		t.Errorf("AKIA not found in expanded entries: %+v", entries)
	}
}

func TestWalk_NestedZipInZip(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	inner := buildZip(t, map[string]string{"leak.txt": akia})
	outer := buildZipBytes(t, map[string][]byte{"inner.zip": inner})

	entries, err := Walk("outer.zip", outer, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !containsAKIA(entries, akia) {
		t.Fatalf("AKIA not surfaced from nested zip; got entries: %+v", entries)
	}
	// The composed path proves the nesting trail.
	for _, e := range entries {
		if strings.Contains(e.Path, "inner.zip") && strings.Contains(e.Path, "leak.txt") {
			return
		}
	}
	t.Errorf("expected path to contain both inner.zip and leak.txt; got %+v", entries)
}

func TestWalk_TarGzExpandsThroughGzipThenTar(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	tarBuf := buildTar(t, map[string]string{"leak.txt": akia})
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(tarBuf)
	gw.Close()

	entries, err := Walk("payload.tar.gz", gzBuf.Bytes(), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !containsAKIA(entries, akia) {
		t.Fatalf("AKIA not found through tar.gz pipeline: %+v", entries)
	}
}

func TestWalk_RecursionCap(t *testing.T) {
	// Build a 3-level nesting and run with MaxDepth=2 — the leaf
	// leak should be dropped silently.
	akia := "AKIAIOSFODNN7EXAMPLE"
	level3 := buildZip(t, map[string]string{"leak.txt": akia})
	level2 := buildZipBytes(t, map[string][]byte{"l3.zip": level3})
	level1 := buildZipBytes(t, map[string][]byte{"l2.zip": level2})

	entries, err := Walk("l1.zip", level1, Limits{MaxDepth: 2})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if containsAKIA(entries, akia) {
		t.Fatalf("recursion cap should have dropped the leaf; got %+v", entries)
	}
}

func TestWalk_SizeLimitTrips(t *testing.T) {
	// Build a zip containing one giant entry; cap MaxEntryBytes
	// well below the entry size and assert nothing comes out.
	big := strings.Repeat("A", 100*1024)
	z := buildZip(t, map[string]string{"big.txt": big})

	entries, err := Walk("big.zip", z, Limits{MaxEntryBytes: 1024})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("oversized entry must be dropped; got %d", len(entries))
	}
}

func TestWalk_NotAnArchiveReturnsEmpty(t *testing.T) {
	// Walk on plain text should be a no-op (empty result, no error).
	entries, err := Walk("plain.txt", []byte("just some text"), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for non-archive; got %d", len(entries))
	}
}

// buildZip constructs an in-memory zip from name->content map. Every
// test that needs a zip uses this so zip-format quirks (date, mode)
// stay centralised.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	bytesMap := map[string][]byte{}
	for k, v := range files {
		bytesMap[k] = []byte(v)
	}
	return buildZipBytes(t, bytesMap)
}

func buildZipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip Write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Size: int64(len(content)), Mode: 0o600}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func containsAKIA(entries []Entry, akia string) bool {
	for _, e := range entries {
		if bytes.Contains(e.Data, []byte(akia)) {
			return true
		}
	}
	return false
}
