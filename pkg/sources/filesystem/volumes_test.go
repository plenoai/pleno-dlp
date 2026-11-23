package filesystem

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/archive"
)

func zipFixture(t *testing.T, secret string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("inner/secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(secret))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestChunks_JoinsSplitVolumes(t *testing.T) {
	dir := t.TempDir()
	whole := zipFixture(t, "FIXTURE-JOINED")
	third := len(whole) / 3
	for i, part := range [][]byte{whole[:third], whole[third : 2*third], whole[2*third:]} {
		if err := os.WriteFile(filepath.Join(dir, "data.zip.00"+string(rune('1'+i))), part, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// other.zip.002 is missing: the remaining volumes are scanned alone
	// (other.zip.003 starts mid-stream; it is still emitted so the engine
	// reports its split-volume gap and scans the raw bytes, #958).
	broken := zipFixture(t, "FIXTURE-BROKEN")
	_ = os.WriteFile(filepath.Join(dir, "other.zip.001"), broken[:len(broken)/2], 0o600)
	_ = os.WriteFile(filepath.Join(dir, "other.zip.003"), broken[len(broken)/2:], 0o600)

	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})
	chunks, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range chunks {
		name := filepath.Base(c.SourceMetadata.Filesystem.Path)
		names = append(names, name)
		if name != "data.zip.001" {
			continue
		}
		if c.Open == nil {
			t.Fatal("joined volumes must use a lazy reader")
		}
		r, closer, size, err := c.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		if _, err := r.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, whole) {
			t.Fatalf("joined body differs: %d vs %d bytes", len(got), len(whole))
		}
		entries, err := archive.Walk(name, got, archive.Limits{})
		if err != nil || len(entries) != 1 || string(entries[0].Data) != "FIXTURE-JOINED" {
			t.Fatalf("walk joined: %v %v", entries, err)
		}
	}
	sort.Strings(names)
	want := []string{"data.zip.001", "other.zip.001", "other.zip.003"}
	if len(names) != len(want) {
		t.Fatalf("chunks %q, want %q", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("chunks %q, want %q", names, want)
		}
	}

	// Incremental: unchanged volumes are skipped; touching a continuation
	// volume re-emits the joined set from volume 1.
	state := s.IncrementalState()
	s2 := &Source{}
	mustInit(t, s2, Config{Paths: []string{dir}})
	if err := s2.SetIncrementalState(state); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "data.zip.003"), future, future); err != nil {
		t.Fatal(err)
	}
	chunks, err = drain(t, s2, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || filepath.Base(chunks[0].SourceMetadata.Filesystem.Path) != "data.zip.001" {
		t.Fatalf("incremental rescan emitted %d chunks", len(chunks))
	}
}

func TestChunks_JoinsSpannedZip(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"span.z01", "span.zip"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "archive", "testdata", "zipspan", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A plain zip with no ".z01" sibling is still scanned as itself.
	_ = os.WriteFile(filepath.Join(dir, "plain.zip"), zipFixture(t, "FIXTURE-PLAIN"), 0o600)

	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})
	chunks, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	found := false
	for _, c := range chunks {
		name := filepath.Base(c.SourceMetadata.Filesystem.Path)
		names = append(names, name)
		if name != "span.z01" {
			continue
		}
		r, closer, size, err := c.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		_, err = r.ReadAt(got, 0)
		_ = closer.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries, err := archive.Walk(name, got, archive.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			found = found || string(e.Data) == "FIXTURE-SPAN-SECRET\n"
		}
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "plain.zip" || names[1] != "span.z01" || !found {
		t.Fatalf("chunks %q found=%v", names, found)
	}
}

// TestChunks_EmitsOrphanSpanTerminal pins #958 for the filesystem source.
func TestChunks_EmitsOrphanSpanTerminal(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "archive", "testdata", "zipspan", "span.zip"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "span.zip"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})
	chunks, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || filepath.Base(chunks[0].SourceMetadata.Filesystem.Path) != "span.zip" {
		t.Fatalf("orphan terminal not emitted: %d chunks", len(chunks))
	}
}
