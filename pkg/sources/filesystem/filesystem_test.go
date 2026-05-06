package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-secret-scanner/pkg/sources"
)

// drain reads chunks from ch until either Chunks() returns or the deadline
// fires. The first return is the chunks observed, the second is whatever
// Chunks() returned.
func drain(t *testing.T, s *Source, deadline time.Duration) ([]*sources.Chunk, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	ch := make(chan *sources.Chunk, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Chunks(ctx, ch); close(ch) }()
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	return got, <-errCh
}

func mustInit(t *testing.T, s *Source, cfg Config) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 4); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestChunks_EmitsTextFile(t *testing.T) {
	dir := t.TempDir()
	want := []byte("dummy AKIA1234567890ABCD12 secret 0123456789012345678901234567890123456789")
	path := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks returned %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	c := got[0]
	if !bytes.Equal(c.Data, want) {
		t.Fatalf("data mismatch:\n got %q\nwant %q", c.Data, want)
	}
	if c.SourceMetadata.Filesystem == nil {
		t.Fatal("Filesystem metadata not set")
	}
	abs, _ := filepath.Abs(path)
	if c.SourceMetadata.Filesystem.Path != abs {
		t.Fatalf("path mismatch: got %q want %q", c.SourceMetadata.Filesystem.Path, abs)
	}
	if c.SourceMetadata.Filesystem.Line != 1 {
		t.Fatalf("Line: got %d want 1", c.SourceMetadata.Filesystem.Line)
	}
	if c.SourceType != sources.SourceFilesystem {
		t.Fatalf("SourceType: got %v", c.SourceType)
	}
}

func TestChunks_SkipsBinaryFile(t *testing.T) {
	dir := t.TempDir()
	bin := append([]byte("hello\x00world"), bytes.Repeat([]byte{0x42}, 100)...)
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), bin, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("text only"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk (binary skipped), got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "ok.txt") {
		t.Fatalf("expected ok.txt, got %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestChunks_SkipsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("A"), 2048)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), big, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "small.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}, MaxSizeBytes: 1024})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want only small.txt, got %d chunks", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "small.txt") {
		t.Fatalf("unexpected file: %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestInit_MissingPath(t *testing.T) {
	s := &Source{}
	cfg := Config{Paths: []string{filepath.Join(t.TempDir(), "does-not-exist")}}
	raw, _ := json.Marshal(cfg)
	err := s.Init(context.Background(), "test", 1, 2, false, raw, 1)
	if err == nil {
		t.Fatal("Init should error on missing path")
	}
}

func TestInit_NoPaths(t *testing.T) {
	s := &Source{}
	raw, _ := json.Marshal(Config{})
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 1); err == nil {
		t.Fatal("Init should error when paths empty")
	}
}

func TestChunks_ContextCancel(t *testing.T) {
	// Fill a directory with enough small files that Chunks cannot finish
	// before we cancel; with an unbuffered channel, the first send blocks
	// until cancel propagates.
	dir := t.TempDir()
	for i := 0; i < 64; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strings.Repeat("x", i+1)+".txt"), []byte("payload"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *sources.Chunk) // unbuffered: first send blocks until consumer or ctx
	errCh := make(chan error, 1)
	go func() { errCh <- s.Chunks(ctx, ch) }()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Chunks did not return after cancel")
	}
}

func TestChunks_SkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("real"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	// Exactly one chunk — the real file. The symlink must not be followed.
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "real.txt") {
		t.Fatalf("unexpected file: %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestRegistry_FilesystemRegistered(t *testing.T) {
	s := sources.New(sources.SourceFilesystem)
	if s == nil {
		t.Fatal("filesystem source not registered")
	}
	if s.Type() != sources.SourceFilesystem {
		t.Fatalf("Type mismatch: %v", s.Type())
	}
}
