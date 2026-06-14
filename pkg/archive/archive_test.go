package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os/exec"
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
		{"tar", append(bytes.Repeat([]byte{0}, 257), []byte("ustar\x00")...), true},
		{"bzip2", []byte{0x42, 0x5a, 0x68, 0x39}, true},
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
	if _, err := gw.Write(tarBuf); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	entries, err := Walk("payload.tar.gz", gzBuf.Bytes(), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !containsAKIA(entries, akia) {
		t.Fatalf("AKIA not found through tar.gz pipeline: %+v", entries)
	}
}

func TestWalk_RecursionCap(t *testing.T) {
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

func TestWalk_TarBz2ExpandsThroughBzip2ThenTar(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	tarBuf := buildTar(t, map[string]string{"leak.txt": akia})
	bz2Buf := buildBzip2(t, tarBuf)

	entries, err := Walk("payload.tar.bz2", bz2Buf, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !containsAKIA(entries, akia) {
		t.Fatalf("AKIA not found through tar.bz2 pipeline: %+v", entries)
	}
}

func TestWalk_NotAnArchiveReturnsEmpty(t *testing.T) {
	entries, err := Walk("plain.txt", []byte("just some text"), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for non-archive; got %d", len(entries))
	}
}

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

// buildBzip2 compresses data using the system bzip2 binary.
// Go stdlib has no bzip2 writer; the test is skipped when bzip2 is absent.
func buildBzip2(t *testing.T, data []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("bzip2"); err != nil {
		t.Skip("bzip2 binary not found; skipping bzip2 round-trip test")
	}
	cmd := exec.Command("bzip2", "-c")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bzip2 compress: %v", err)
	}
	return out
}

func containsAKIA(entries []Entry, akia string) bool {
	for _, e := range entries {
		if bytes.Contains(e.Data, []byte(akia)) {
			return true
		}
	}
	return false
}
