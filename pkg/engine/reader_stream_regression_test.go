package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
)

const (
	streamRawToken     = "STREAM_RAW_TOKEN_0123456789"
	streamRawTokenTwo  = "STREAM_RAW_TOKEN_ABCDEFGHIJ"
	streamDecodedToken = "STREAM_DECODED_TOKEN_0123456789"
	streamFullMarker   = "STREAM_FULL_CHUNK_BEGIN"
	streamFullToken    = "STREAM_FULL_CHUNK_END_TOKEN"
)

// readerParityDetector is deliberately reader-first. Its FromData method is
// still useful for the in-memory reference run, while readerOnly makes the
// lazy run fail if the engine silently falls back to the old byte-slice path.
// The detector is also a full-chunk detector so a short window cannot satisfy
// the marker/token pair used by the long-input tests.
type readerParityDetector struct {
	readerOnly    bool
	boundedReader bool
	fromData      atomic.Int64
	fromReader    atomic.Int64
}

func (d *readerParityDetector) Type() detectors.DetectorType { return detectors.AWS }

func (d *readerParityDetector) Keywords() []string {
	return []string{streamRawToken, streamRawTokenTwo, streamDecodedToken, streamFullMarker, streamFullToken}
}

func (*readerParityDetector) WantsFullChunk() bool { return true }

func (d *readerParityDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	d.fromData.Add(1)
	if d.readerOnly {
		return nil, errors.New("reader-only detector was called through FromData")
	}
	return streamParityResults(data), nil
}

func (d *readerParityDetector) FromReader(ctx context.Context, _ bool, r io.ReaderAt, size int64) ([]detectors.Result, error) {
	d.fromReader.Add(1)
	if r == nil || size < 0 {
		return nil, errors.New("invalid reader input")
	}
	if d.boundedReader {
		return streamCanaryResults(ctx, r, size)
	}
	data, err := io.ReadAll(io.NewSectionReader(r, 0, size))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("reader returned %d bytes, want %d", len(data), size)
	}
	return streamParityResults(data), nil
}

func streamParityResults(data []byte) []detectors.Result {
	var out []detectors.Result
	appendOccurrences := func(token string) {
		needle := []byte(token)
		for offset := 0; ; {
			idx := bytes.Index(data[offset:], needle)
			if idx < 0 {
				return
			}
			offset += idx
			out = append(out, streamResult(token))
			offset += len(needle)
		}
	}
	appendOccurrences(streamRawToken)
	appendOccurrences(streamRawTokenTwo)
	appendOccurrences(streamDecodedToken)
	if bytes.Contains(data, []byte(streamFullMarker)) && bytes.Contains(data, []byte(streamFullToken)) {
		out = append(out, streamResult(streamFullToken))
	}
	return out
}

func streamResult(raw string) detectors.Result {
	return detectors.Result{
		DetectorType: detectors.AWS,
		Raw:          []byte(raw),
		Redacted:     raw[:min(8, len(raw))] + "...",
		ExtraData:    map[string]string{"fixture": "reader-stream"},
	}
}

// streamCanaryResults scans a long reader with a bounded carry. The test
// detector therefore does not hide an engine regression by retaining a 64 MiB
// input just to find a token at its end.
func streamCanaryResults(ctx context.Context, r io.ReaderAt, size int64) ([]detectors.Result, error) {
	const blockSize = 32 * 1024
	carrySize := max(len(streamFullMarker), len(streamFullToken)) - 1
	carry := make([]byte, 0, carrySize)
	block := make([]byte, blockSize)
	reader := io.NewSectionReader(r, 0, size)
	var consumed int64
	var marker, token bool
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := reader.Read(block)
		if n > 0 {
			consumed += int64(n)
			window := make([]byte, 0, len(carry)+n)
			window = append(window, carry...)
			window = append(window, block[:n]...)
			marker = marker || bytes.Contains(window, []byte(streamFullMarker))
			token = token || bytes.Contains(window, []byte(streamFullToken))
			if len(window) > carrySize {
				carry = append(carry[:0], window[len(window)-carrySize:]...)
			} else {
				carry = append(carry[:0], window...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	if consumed != size {
		return nil, fmt.Errorf("reader returned %d bytes, want %d", consumed, size)
	}
	if marker && token {
		return []detectors.Result{streamResult(streamFullToken)}, nil
	}
	return nil, nil
}

type readerRegressionSource struct{ chunk *sources.Chunk }

func (*readerRegressionSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

func (*readerRegressionSource) Type() sources.SourceType { return sources.SourceFilesystem }

func (s *readerRegressionSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	select {
	case ch <- s.chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func memoryReaderChunk(data []byte, path string) *sources.Chunk {
	return &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: path, Line: 1},
		},
	}
}

func lazyReaderChunk(data []byte, path string) *sources.Chunk {
	return &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Open: func(ctx context.Context) (io.ReaderAt, io.Closer, int64, error) {
			if err := ctx.Err(); err != nil {
				return nil, nil, 0, err
			}
			return bytes.NewReader(data), io.NopCloser(strings.NewReader("")), int64(len(data)), nil
		},
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: path, Line: 1},
		},
	}
}

type streamFindingSnapshot struct {
	Raw         string
	Path        string
	Line        int
	DecodedFrom string
	ArchivePath string
}

func snapshotStreamFindings(findings []Finding) []streamFindingSnapshot {
	out := make([]streamFindingSnapshot, 0, len(findings))
	for _, finding := range findings {
		var path string
		var line int
		if finding.Chunk != nil && finding.Chunk.SourceMetadata.Filesystem != nil {
			path = finding.Chunk.SourceMetadata.Filesystem.Path
			line = finding.Chunk.SourceMetadata.Filesystem.Line
		}
		out = append(out, streamFindingSnapshot{
			Raw:         string(finding.Result.Raw),
			Path:        path,
			Line:        line,
			DecodedFrom: finding.Result.ExtraData["decoded_from"],
			ArchivePath: finding.Result.ExtraData["archive_path"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Raw != out[j].Raw {
			return out[i].Raw < out[j].Raw
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].DecodedFrom+out[i].ArchivePath < out[j].DecodedFrom+out[j].ArchivePath
	})
	return out
}

func runReaderRegression(t *testing.T, chunk *sources.Chunk, detector *readerParityDetector) ([]Finding, error) {
	t.Helper()
	sink := &engineRecordingSink{}
	engine := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, NewDedup(sink))
	err := engine.Run(context.Background(), &readerRegressionSource{chunk: chunk})
	return sink.Findings(), err
}

func TestReaderDetectorStreamMatchesInMemoryRawDecodedMetadataAndDedup(t *testing.T) {
	const path = "/fixture/stream-secrets.txt"
	header := []byte("header\n" + streamRawToken + " " + streamRawToken + "\n" + streamRawTokenTwo + "\n")
	if len(header) >= maxWindowSize-7 {
		t.Fatalf("fixture header unexpectedly exceeds window alignment")
	}
	payload := append([]byte("decoded payload "+streamDecodedToken+" "+streamDecodedToken+" "), bytes.Repeat([]byte{'z'}, 64<<10)...)
	encoded := base64.StdEncoding.EncodeToString(payload)
	data := append(append(append([]byte(nil), header...), bytes.Repeat([]byte{' '}, maxWindowSize-7-len(header))...), encoded...)

	memoryDetector := &readerParityDetector{}
	memoryFindings, err := runReaderRegression(t, memoryReaderChunk(data, path), memoryDetector)
	if err != nil {
		t.Fatalf("in-memory reference: %v", err)
	}

	streamDetector := &readerParityDetector{readerOnly: true}
	streamFindings, err := runReaderRegression(t, lazyReaderChunk(data, path), streamDetector)
	if err != nil {
		t.Fatalf("reader stream: %v", err)
	}
	if streamDetector.fromReader.Load() == 0 {
		t.Fatal("lazy chunk never reached ReaderDetector.FromReader")
	}
	if streamDetector.fromData.Load() != 0 {
		t.Fatalf("lazy chunk fell back to FromData %d times", streamDetector.fromData.Load())
	}

	want := snapshotStreamFindings(memoryFindings)
	got := snapshotStreamFindings(streamFindings)
	if len(want) != 3 {
		t.Fatalf("in-memory findings = %#v, want one deduped duplicate, a second raw location, and one decoded result", want)
	}
	if !equalStreamSnapshots(got, want) {
		t.Fatalf("lazy findings differ:\n got %#v\nwant %#v", got, want)
	}
	if got[0].Path != path || got[1].Path != path || got[2].Path != path {
		t.Fatalf("filesystem metadata path was not preserved: %#v", got)
	}
	linesByRaw := make(map[string]int, len(got))
	for _, finding := range got {
		linesByRaw[finding.Raw] = finding.Line
	}
	if linesByRaw[streamRawToken] != 2 || linesByRaw[streamRawTokenTwo] != 3 || linesByRaw[streamDecodedToken] != 1 {
		t.Fatalf("line metadata = %#v, want raw lines 2/3 and decoded line 1", linesByRaw)
	}
}

func equalStreamSnapshots(a, b []streamFindingSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReaderDetectorStreams64MiBPlainLongLine(t *testing.T) {
	const size = 64 << 20
	dir := t.TempDir()
	path := filepath.Join(dir, "long-line.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	marker := []byte(streamFullMarker + " ")
	if _, err := f.Write(marker); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	remaining := size - len(marker) - len(streamFullToken)
	if remaining <= 0 {
		t.Fatal("invalid long-line size")
	}
	block := bytes.Repeat([]byte{'x'}, 1<<20)
	for remaining > 0 {
		n := len(block)
		if int64(n) > int64(remaining) {
			n = remaining
		}
		if _, err := f.Write(block[:n]); err != nil {
			t.Fatalf("write padding: %v", err)
		}
		remaining -= n
	}
	if _, err := f.WriteString(streamFullToken); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var cfg filesystem.Config
	cfg.Paths = []string{dir}
	cfg.MaxSizeBytes = size + 1
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	src := &filesystem.Source{}
	if err := src.Init(context.Background(), "filesystem", 1, 1, false, rawCfg, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	detector := &readerParityDetector{readerOnly: true, boundedReader: true}
	sink := &engineRecordingSink{}
	engine := NewWithDetectors([]detectors.Detector{detector}, Options{Concurrency: 1}, NewDedup(sink))
	stats, err := engine.RunWithStats(context.Background(), src)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if stats.Bytes != size {
		t.Fatalf("scanned bytes = %d, want %d", stats.Bytes, size)
	}
	findings := snapshotStreamFindings(sink.Findings())
	if len(findings) != 1 || findings[0].Raw != streamFullToken || findings[0].Line != 1 {
		t.Fatalf("long-line findings = %#v, want one line-1 full-chunk finding", findings)
	}
	if detector.fromReader.Load() == 0 || detector.fromData.Load() != 0 {
		t.Fatalf("reader dispatch counts: FromReader=%d FromData=%d", detector.fromReader.Load(), detector.fromData.Load())
	}
}

func TestReaderDetectorStreamMatchesInMemoryLargeArchiveLeaf(t *testing.T) {
	const (
		path      = "/fixture/large.zip"
		entryName = "nested/large-leaf.txt"
	)
	leaf := append([]byte(streamFullMarker+"\n"), bytes.Repeat([]byte("archive-padding\n"), (2<<20)/len("archive-padding\n"))...)
	leaf = append(leaf, []byte(streamFullToken)...)
	archiveData := makeStoredZip(t, entryName, leaf)

	memoryDetector := &readerParityDetector{}
	memoryFindings, err := runReaderRegression(t, memoryReaderChunk(archiveData, path), memoryDetector)
	if err != nil {
		t.Fatalf("in-memory archive reference: %v", err)
	}
	streamDetector := &readerParityDetector{readerOnly: true, boundedReader: true}
	streamFindings, err := runReaderRegression(t, lazyReaderChunk(archiveData, path), streamDetector)
	if err != nil {
		t.Fatalf("streamed archive: %v", err)
	}
	if !equalStreamSnapshots(snapshotStreamFindings(streamFindings), snapshotStreamFindings(memoryFindings)) {
		t.Fatalf("streamed archive findings differ:\n got %#v\nwant %#v", snapshotStreamFindings(streamFindings), snapshotStreamFindings(memoryFindings))
	}
	got := snapshotStreamFindings(streamFindings)
	wantArchivePath := path + "!" + entryName
	if len(got) != 1 || got[0].ArchivePath != wantArchivePath || got[0].Path != path {
		t.Fatalf("archive metadata = %#v, want one %s finding under %s", got, wantArchivePath, path)
	}
	if streamDetector.fromReader.Load() == 0 || streamDetector.fromData.Load() != 0 {
		t.Fatalf("archive reader dispatch counts: FromReader=%d FromData=%d", streamDetector.fromReader.Load(), streamDetector.fromData.Load())
	}
}

func makeStoredZip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: name, Method: zip.Store}
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
