package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func zipOf(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestArchiveMaxDepthOption pins Options.ArchiveMaxDepth (--extraction-depth):
// a secret nested four zips deep is found at the cap and missed below it.
func TestArchiveMaxDepthOption(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	data := zipOf(t, "leaf.env", []byte("AWS_KEY="+akia+"\n"))
	for i := 0; i < 3; i++ {
		data = zipOf(t, "nested.zip", data)
	}
	count := func(depth int) int {
		sink := &recordingSink{}
		eng := NewWithDetectors([]detectors.Detector{fakeDetector{needle: akia}}, Options{Concurrency: 1, ArchiveMaxDepth: depth}, sink)
		_ = eng.Run(context.Background(), fakeSource{data: data})
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.findings)
	}
	if n := count(1); n != 0 {
		t.Fatalf("depth 1 found %d", n)
	}
	if n := count(8); n != 1 {
		t.Fatalf("depth 8 found %d", n)
	}
	e := &Engine{opts: Options{ArchiveMaxDepth: 99}}
	if e.archiveMaxDepth() != MaxArchiveMaxDepth {
		t.Fatal("not clamped")
	}
}
