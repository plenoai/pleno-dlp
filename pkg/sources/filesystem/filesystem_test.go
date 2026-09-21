package filesystem

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
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

func TestChunks_LargeFileUsesLazyReaderAt(t *testing.T) {
	dir := t.TempDir()
	want := bytes.Repeat([]byte("credential=plain-text\n"), filesystemLazyThreshold/len("credential=plain-text\n")+1)
	path := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}, MaxSizeBytes: int64(len(want) + 1)})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks returned %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	chunk := got[0]
	if chunk.Data != nil {
		t.Fatalf("large chunk retained %d body bytes", len(chunk.Data))
	}
	if chunk.Open == nil {
		t.Fatal("large chunk has no lazy opener")
	}
	reader, closer, size, err := chunk.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if reader == nil || closer == nil {
		t.Fatal("Open returned incomplete reader ownership")
	}
	data, err := io.ReadAll(io.NewSectionReader(reader, 0, size))
	closeErr := closer.Close()
	if err != nil {
		t.Fatalf("read lazy body: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close lazy body: %v", closeErr)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("lazy body changed: got %d bytes, want %d", len(data), len(want))
	}
	abs, _ := filepath.Abs(path)
	if chunk.SourceMetadata.Filesystem == nil || chunk.SourceMetadata.Filesystem.Path != abs {
		t.Fatalf("metadata path = %#v, want %q", chunk.SourceMetadata.Filesystem, abs)
	}
}

func TestOpenFileReaderAtDetectsAppendBeforeClose(t *testing.T) {
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("plain text\n"), filesystemLazyThreshold/len("plain text\n")+1)
	path := filepath.Join(dir, "growing.txt")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reader, closer, size, err := openFileReaderAt(context.Background(), path, int64(len(payload)+len("appended\n")))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if reader == nil || closer == nil || size != int64(len(payload)) {
		t.Fatalf("open result = (%v, %v, %d), want reader, closer, and %d bytes", reader, closer, size, len(payload))
	}
	appendFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open append handle: %v", err)
	}
	if _, err := appendFile.WriteString("appended\n"); err != nil {
		_ = appendFile.Close()
		t.Fatalf("append: %v", err)
	}
	if err := appendFile.Close(); err != nil {
		t.Fatalf("close append handle: %v", err)
	}
	if err := closer.Close(); !errors.Is(err, errFileChangedDuringScan) {
		t.Fatalf("close after append = %v, want file-change error", err)
	}
}

func TestOpenFileReaderAtPreservesAdmissionSkips(t *testing.T) {
	dir := t.TempDir()
	binaryData := bytes.Repeat([]byte{'x'}, filesystemLazyThreshold+1)
	binaryData[10] = 0
	binaryPath := filepath.Join(dir, "binary.bin")
	if err := os.WriteFile(binaryPath, binaryData, 0o600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	overLimitPath := filepath.Join(dir, "over-limit.txt")
	if err := os.WriteFile(overLimitPath, bytes.Repeat([]byte{'x'}, filesystemLazyThreshold+1), 0o600); err != nil {
		t.Fatalf("write over-limit: %v", err)
	}

	reader, closer, size, err := openFileReaderAt(context.Background(), binaryPath, int64(len(binaryData)))
	if err != nil || reader != nil || closer != nil || size != 0 {
		t.Fatalf("binary admission = (%v, %v, %d, %v), want nil reader skip", reader, closer, size, err)
	}
	reader, closer, size, err = openFileReaderAt(context.Background(), overLimitPath, filesystemLazyThreshold)
	if err != nil || reader != nil || closer != nil || size != 0 {
		t.Fatalf("over-limit admission = (%v, %v, %d, %v), want nil reader skip", reader, closer, size, err)
	}
}

func TestOpenFileReaderAtHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, filesystemLazyThreshold+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, closer, size, err := openFileReaderAt(ctx, path, filesystemLazyThreshold+2)
	if !errors.Is(err, context.Canceled) || reader != nil || closer != nil || size != 0 {
		t.Fatalf("canceled admission = (%v, %v, %d, %v), want cancellation", reader, closer, size, err)
	}
}

func TestChunks_EmitsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks returned %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 empty-file chunk, got %d", len(got))
	}
	if got[0].Data == nil || len(got[0].Data) != 0 {
		t.Fatalf("empty-file data = %#v, want non-nil empty slice", got[0].Data)
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

func TestChunks_EmitsUTF16Text(t *testing.T) {
	for _, tc := range []struct {
		name   string
		little bool
	}{
		{name: "utf16le", little: true},
		{name: "utf16be", little: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			want := encodeUTF16("CONFIG_CREDENTIAL=filesystem-utf16-fixture", tc.little, true)
			path := filepath.Join(dir, tc.name+".txt")
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			s := &Source{}
			mustInit(t, s, Config{Paths: []string{dir}})

			got, err := drain(t, s, 5*time.Second)
			if err != nil {
				t.Fatalf("Chunks: %v", err)
			}
			if len(got) != 1 || !bytes.Equal(got[0].Data, want) {
				t.Fatalf("UTF-16 file was dropped or changed: chunks=%d", len(got))
			}
		})
	}
}

func TestChunks_EmitsBOMlessUTF16Text(t *testing.T) {
	dir := t.TempDir()
	want := encodeUTF16("CONFIG_CREDENTIAL=filesystem-utf16-no-bom", true, false)
	if err := os.WriteFile(filepath.Join(dir, "utf16.txt"), want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Data, want) {
		t.Fatalf("BOM-less UTF-16 file was dropped or changed: chunks=%d", len(got))
	}
}

func TestChunks_SkipsNULBinaryWithUTF16LikeShape(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 128)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0xff
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("NUL binary was admitted as UTF-16 text: %d chunks", len(got))
	}
}

func TestChunks_EmitsArchiveAfterPrefixSniff(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("secret.txt")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := entry.Write([]byte("archive content")); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	data := buf.Bytes()
	if !isBinary(data) || !archive.LooksLikeArchive(data) {
		t.Fatal("fixture must exercise binary archive prefix")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.zip")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Data, data) {
		t.Fatalf("archive chunk lost after prefix sniff: chunks=%d", len(got))
	}
}

func TestReadFile_DropsGrowthPastMaxSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "growing.txt")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	s := &Source{cfg: Config{MaxSizeBytes: 4}}
	data, err := s.readFile(context.Background(), f, 2)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if data != nil {
		t.Fatalf("readFile returned %d bytes after crossing max size", len(data))
	}
}

func TestReadFile_SniffsBeyondStaleSizeHint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grown.bin")
	if err := os.WriteFile(path, []byte("prefix\x00binary"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	s := &Source{cfg: Config{MaxSizeBytes: 1024}}
	data, err := s.readFile(context.Background(), f, 0)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if data != nil {
		t.Fatalf("stale size hint bypassed binary sniff: %d bytes", len(data))
	}
}

func TestReadFile_ExactSizeKeepsBufferBounded(t *testing.T) {
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("x"), 4096)
	path := filepath.Join(dir, "text.txt")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	s := &Source{cfg: Config{MaxSizeBytes: 1 << 20}}
	data, err := s.readFile(context.Background(), f, int64(len(payload)))
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("readFile changed payload")
	}
	if cap(data) >= 2*len(data) {
		t.Fatalf("buffer capacity %d doubled payload size %d", cap(data), len(data))
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

func TestChunks_IncrementalStateEmitsOnlyChangedFiles(t *testing.T) {
	dir := t.TempDir()
	unchanged := filepath.Join(dir, "unchanged.txt")
	changed := filepath.Join(dir, "changed.txt")
	if err := os.WriteFile(unchanged, []byte("old unchanged"), 0o600); err != nil {
		t.Fatalf("write unchanged: %v", err)
	}
	if err := os.WriteFile(changed, []byte("old changed"), 0o600); err != nil {
		t.Fatalf("write changed: %v", err)
	}
	oldTime := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(unchanged, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes unchanged: %v", err)
	}
	if err := os.Chtimes(changed, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes changed: %v", err)
	}

	first := &Source{}
	mustInit(t, first, Config{Paths: []string{dir}})
	if got, err := drain(t, first, 5*time.Second); err != nil || len(got) != 2 {
		t.Fatalf("first scan got %d chunks err=%v, want 2 nil", len(got), err)
	}
	previous := first.IncrementalState()
	if len(previous) == 0 {
		t.Fatal("first scan did not produce incremental state")
	}

	newTime := oldTime.Add(time.Hour)
	if err := os.WriteFile(changed, []byte("new changed"), 0o600); err != nil {
		t.Fatalf("rewrite changed: %v", err)
	}
	if err := os.Chtimes(changed, newTime, newTime); err != nil {
		t.Fatalf("chtimes changed v2: %v", err)
	}

	second := &Source{}
	mustInit(t, second, Config{Paths: []string{dir}})
	if err := second.SetIncrementalState(previous); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	got, err := drain(t, second, 5*time.Second)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want only changed file, got %d chunks", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "changed.txt") {
		t.Fatalf("unexpected file: %s", got[0].SourceMetadata.Filesystem.Path)
	}
	if string(got[0].Data) != "new changed" {
		t.Fatalf("unexpected data: %q", got[0].Data)
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

func encodeUTF16(s string, little, bom bool) []byte {
	data := make([]byte, 0, len(s)*2+2)
	if bom {
		if little {
			data = append(data, 0xff, 0xfe)
		} else {
			data = append(data, 0xfe, 0xff)
		}
	}
	for _, r := range s {
		u := uint16(r)
		if little {
			data = append(data, byte(u), byte(u>>8))
		} else {
			data = append(data, byte(u>>8), byte(u))
		}
	}
	return data
}
