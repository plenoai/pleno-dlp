package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// openedSource emits its body through Chunk.Open, the replayable path large
// filesystem/object bodies take.
type openedSource struct{ data []byte }

func (openedSource) Init(context.Context, string, int64, int64, bool, []byte, int) error { return nil }
func (openedSource) Type() sources.SourceType                                            { return sources.SourceFilesystem }
func (s openedSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	data := s.data
	c := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			return bytes.NewReader(data), nil, int64(len(data)), nil
		},
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "/tmp/fake.zip", Line: 1}},
	}
	select {
	case ch <- c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestArchiveRawFallbackScansUnopenableArchives pins #970: a container that
// is recognised as an archive but fails to open or expand still has its raw
// bytes scanned, and the coverage gap is still reported.
func TestArchiveRawFallbackScansUnopenableArchives(t *testing.T) {
	const akia = "AKIA" + "QYLPMN5HHHFPZAM2"
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "k.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("aws=" + akia + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	full := zipped.Bytes()
	cases := map[string][]byte{
		"spanned-head":  []byte("PK\x07\x08PK\x03\x04 junk " + akia + " tail"),
		"truncated-zip": full[:len(full)-30],
		"corrupt-gzip":  append([]byte{0x1f, 0x8b, 0x08, 0x00}, []byte(" not deflate "+akia)...),
	}
	for name, body := range cases {
		for _, mode := range []string{"data", "open"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				sink := &recordingSink{}
				eng := NewWithDetectors([]detectors.Detector{fakeDetector{needle: akia}}, Options{Concurrency: 1}, sink)
				var src sources.Source = fakeSource{data: body}
				if mode == "open" {
					src = openedSource{data: body}
				}
				err := eng.Run(context.Background(), src)
				var degraded *DegradedError
				if !errors.As(err, &degraded) || degraded.Counts[FailureArchive] == 0 {
					t.Fatalf("Run error = %v, want an archive coverage gap", err)
				}
				sink.mu.Lock()
				defer sink.mu.Unlock()
				if len(sink.findings) == 0 {
					t.Fatalf("raw bytes of an unopenable archive were not scanned")
				}
			})
		}
	}
}
