package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "max-depth" {
		t.Fatalf("Walk error=%v, want max-depth PartialError", err)
	}
	if containsAKIA(entries, akia) {
		t.Fatalf("recursion cap should have dropped the leaf; got %+v", entries)
	}
}

func TestWalk_SizeLimitTrips(t *testing.T) {
	big := strings.Repeat("A", 100*1024)
	z := buildZip(t, map[string]string{"big.txt": big})

	entries, err := Walk("big.zip", z, Limits{MaxEntryBytes: 1024})
	var partial *PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("Walk error=%v, want PartialError", err)
	}
	if len(entries) != 0 {
		t.Errorf("oversized entry must be dropped; got %d", len(entries))
	}
}

func TestWalk_PartialBudgetsPathsCorruptionAndCancellation(t *testing.T) {
	t.Run("expanded", func(t *testing.T) {
		z := buildZip(t, map[string]string{"ok": "ok", "large": strings.Repeat("x", 20)})
		entries, err := Walk("x.zip", z, Limits{MaxEntryBytes: 100, MaxExpandedBytes: 3})
		if err == nil || len(entries) != 1 {
			t.Fatalf("entries=%v err=%v", entries, err)
		}
	})
	t.Run("files exact and breach", func(t *testing.T) {
		z := buildZip(t, map[string]string{"a": "a", "b": "b"})
		entries, err := Walk("x.zip", z, Limits{MaxFiles: 1})
		if err == nil || len(entries) != 1 {
			t.Fatalf("entries=%v err=%v", entries, err)
		}
		one := buildZip(t, map[string]string{"a": "a"})
		if entries, err := Walk("x.zip", one, Limits{MaxFiles: 1}); err != nil || len(entries) != 1 {
			t.Fatalf("exact boundary entries=%v err=%v", entries, err)
		}
	})
	t.Run("traversal symlink corrupt", func(t *testing.T) {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, _ := zw.Create("../escape")
		_, _ = w.Write([]byte("bad"))
		w, _ = zw.Create(`..\windows-escape`)
		_, _ = w.Write([]byte("bad"))
		h := &zip.FileHeader{Name: "link"}
		h.SetMode(os.ModeSymlink | 0o777)
		w, _ = zw.CreateHeader(h)
		_, _ = w.Write([]byte("target"))
		_ = zw.Close()
		entries, err := Walk("x.zip", b.Bytes(), Limits{})
		if err == nil || len(entries) != 0 {
			t.Fatalf("entries=%v err=%v", entries, err)
		}
		_, err = Walk("bad.zip", []byte{'P', 'K', 3, 4}, Limits{})
		var partial *PartialError
		if !errors.As(err, &partial) || partial.Kind != "corrupt-archive" {
			t.Fatalf("corrupt err=%v", err)
		}
	})
	t.Run("terminal file budget stops traversal and bounds errors", func(t *testing.T) {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for i := 0; i < 5000; i++ {
			w, err := zw.Create(fmt.Sprintf("%05d", i))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte("x"))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := Walk("many.zip", b.Bytes(), Limits{MaxFiles: 2})
		if err == nil || len(entries) != 2 {
			t.Fatalf("entries=%d err=%v", len(entries), err)
		}
		var joined interface{ Unwrap() []error }
		if errors.As(err, &joined) && len(joined.Unwrap()) > 32 {
			t.Fatalf("retained errors=%d, want <=32", len(joined.Unwrap()))
		}
	})
	t.Run("timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := WalkContext(ctx, "x.zip", buildZip(t, map[string]string{"a": strings.Repeat("x", 1000)}), Limits{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestWalkStreamContextSpills0600AndCleansEveryPath(t *testing.T) {
	buildStoredZip := func(data []byte) []byte {
		t.Helper()
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		header := &zip.FileHeader{Name: "large.bin", Method: zip.Store}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}

	payload := bytes.Repeat([]byte("bounded-spool-"), 64)
	archiveData := buildStoredZip(payload)
	for _, tc := range []struct {
		name      string
		callback  error
		wantError bool
	}{
		{name: "success"},
		{name: "callback error", callback: errors.New("stop callback"), wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			visited := 0
			err := walkStreamContext(context.Background(), "large.zip", bytes.NewReader(archiveData), int64(len(archiveData)), Limits{}, func(entry StreamEntry) error {
				visited++
				files, err := os.ReadDir(tempDir)
				if err != nil {
					t.Fatal(err)
				}
				if len(files) < 2 {
					t.Fatalf("active spool files=%d, want root and expanded entry", len(files))
				}
				for _, file := range files {
					info, err := file.Info()
					if err != nil {
						t.Fatal(err)
					}
					if got := info.Mode().Perm(); got != 0o600 {
						t.Fatalf("spool mode=%#o, want 0600", got)
					}
				}
				got, err := io.ReadAll(entry.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("spooled payload length=%d, want %d", len(got), len(payload))
				}
				return tc.callback
			}, spoolOptions{threshold: 64, tempDir: tempDir})
			if (err != nil) != tc.wantError {
				t.Fatalf("walk error=%v, wantError=%t", err, tc.wantError)
			}
			if visited != 1 {
				t.Fatalf("visited=%d, want 1", visited)
			}
			files, readErr := os.ReadDir(tempDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(files) != 0 {
				t.Fatalf("spool files leaked after return: %v", files)
			}
		})
	}
}

func TestWalkStreamContextCountsNestedIntermediateBytes(t *testing.T) {
	leaf := []byte("leaf data counts after its containing archive")
	inner := buildZipBytes(t, map[string][]byte{"leaf.txt": leaf})
	outer := buildZipBytes(t, map[string][]byte{"inner.zip": inner})
	limit := int64(len(inner) + len(leaf) - 1)
	emitted := 0
	err := WalkStreamContext(context.Background(), "outer.zip", bytes.NewReader(outer), int64(len(outer)), Limits{
		MaxEntryBytes:    int64(len(inner) + 1),
		MaxExpandedBytes: limit,
	}, func(StreamEntry) error {
		emitted++
		return nil
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "max-expanded-bytes" {
		t.Fatalf("error=%v, want max-expanded-bytes", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d, want 0", emitted)
	}
}

func TestWalkStreamContextAppliesFileLimitAfterZipPreflight(t *testing.T) {
	archiveData := buildZip(t, map[string]string{"a": "a", "b": "b", "c": "c"})
	emitted := 0
	err := WalkStreamContext(context.Background(), "many.zip", bytes.NewReader(archiveData), int64(len(archiveData)), Limits{MaxFiles: 2}, func(StreamEntry) error {
		emitted++
		return nil
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "max-files" {
		t.Fatalf("error=%v, want max-files", err)
	}
	if emitted != 2 {
		t.Fatalf("emitted=%d, want 2 validated partial entries", emitted)
	}
}

func TestWalkStreamContextRejectsZipHardHeaderCapBeforeEmission(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for i := 0; i <= maxArchiveHeaders; i++ {
		entry, err := writer.Create(fmt.Sprintf("%05d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	emitted := 0
	err := WalkStreamContext(context.Background(), "headers.zip", bytes.NewReader(buffer.Bytes()), int64(buffer.Len()), Limits{MaxFiles: maxArchiveHeaders + 1}, func(StreamEntry) error {
		emitted++
		return nil
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "max-headers" {
		t.Fatalf("error=%v, want max-headers", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d, want preflight rejection", emitted)
	}
}

func TestWalkStreamContextEnforcesInputLimit(t *testing.T) {
	archiveData := buildZip(t, map[string]string{"a": "a"})
	err := WalkStreamContext(context.Background(), "input.zip", bytes.NewReader(archiveData), int64(len(archiveData)), Limits{MaxInputBytes: int64(len(archiveData) - 1)}, func(StreamEntry) error {
		return errors.New("unexpected emission")
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "max-input-bytes" {
		t.Fatalf("error=%v, want max-input-bytes", err)
	}
}

func TestWalkStreamContextRejectsOversizedTarMetadataBeforeEmission(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for i := 0; i < 2; i++ {
		header := &tar.Header{
			Name:   strings.Repeat(string(rune('a'+i)), 600<<10),
			Size:   1,
			Mode:   0o600,
			Format: tar.FormatPAX,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	emitted := 0
	err := WalkStreamContext(context.Background(), "metadata.tar", bytes.NewReader(buffer.Bytes()), int64(buffer.Len()), Limits{}, func(StreamEntry) error {
		emitted++
		return nil
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "metadata-bytes" {
		t.Fatalf("error=%v, want metadata-bytes", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d, want preflight rejection", emitted)
	}
}

func TestWalkStreamContextCorruptZipEntryIsNeverEmitted(t *testing.T) {
	archiveData := buildZip(t, map[string]string{"secret.txt": "validated only after CRC"})
	corrupt := append([]byte(nil), archiveData...)
	if len(corrupt) < 30 || !bytes.Equal(corrupt[:4], []byte{'P', 'K', 3, 4}) {
		t.Fatal("fixture has no local ZIP header")
	}
	nameLen := int(corrupt[26]) | int(corrupt[27])<<8
	extraLen := int(corrupt[28]) | int(corrupt[29])<<8
	dataOffset := 30 + nameLen + extraLen
	if dataOffset >= len(corrupt) {
		t.Fatal("fixture has no entry body")
	}
	corrupt[dataOffset] ^= 0xff

	emitted := 0
	err := WalkStreamContext(context.Background(), "corrupt.zip", bytes.NewReader(corrupt), int64(len(corrupt)), Limits{}, func(StreamEntry) error {
		emitted++
		return nil
	})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "corrupt-entry" {
		t.Fatalf("error=%v, want corrupt-entry", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d, want 0", emitted)
	}
}

func TestWalkTarCancellationInterruptsRejectedEntryDiscard(t *testing.T) {
	var archiveData bytes.Buffer
	writer := tar.NewWriter(&archiveData)
	body := bytes.Repeat([]byte("x"), 4096)
	if err := writer.WriteHeader(&tar.Header{Name: "oversized", Size: int64(len(body)), Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "later", Size: 1, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	input := &cancelAfterReader{
		reader:    bytes.NewReader(archiveData.Bytes()),
		remaining: 512 + 16, // one header, then part of tar.Next's body discard
		cancel:    cancel,
	}
	state := &walkState{
		ctx: ctx,
		limits: Limits{
			MaxDepth:         4,
			MaxEntryBytes:    1,
			MaxExpandedBytes: 1 << 20,
			MaxFiles:         10,
		},
		visit: func(StreamEntry) error { return errors.New("unexpected emission") },
	}
	err := state.walkTarReader("payload.tar", contextReader{ctx: ctx, r: input}, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want cancellation during implicit discard", err)
	}
}

type cancelAfterReader struct {
	reader    io.Reader
	remaining int
	cancel    context.CancelFunc
}

func (r *cancelAfterReader) Read(buffer []byte) (int, error) {
	if r.remaining <= 0 {
		r.cancel()
		return 0, context.Canceled
	}
	if len(buffer) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.reader.Read(buffer)
	r.remaining -= n
	if r.remaining == 0 {
		r.cancel()
	}
	return n, err
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
