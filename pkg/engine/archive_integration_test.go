package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestArchiveIntegration_FindsSecretInsideZip drives the full engine
// path with a chunk whose payload is a zip containing a leaked secret.
// Without the archive expansion step the AKIA bytes never reach a
// detector — the zip envelope hides them in compressed form.
func TestArchiveIntegration_FindsSecretInsideZip(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"

	// Build a real zip in memory containing one entry with a leak.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("config.env")
	if err != nil {
		t.Fatalf("zip Create: %v", err)
	}
	if _, err := w.Write([]byte("AWS_KEY=" + akia + "\n")); err != nil {
		t.Fatalf("zip Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}

	sink := &recordingSink{}
	eng := &Engine{
		opts: Options{Concurrency: 1},
		dets: []detectors.Detector{fakeDetector{needle: akia}},
		sink: sink,
	}

	if err := eng.Run(context.Background(), fakeSource{data: buf.Bytes()}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.findings) != 1 {
		t.Fatalf("expected 1 finding inside zip; got %d", len(sink.findings))
	}
	f := sink.findings[0]
	if got := string(f.Result.Raw); got != akia {
		t.Errorf("Raw = %q; want %q", got, akia)
	}
	gotPath := f.Result.ExtraData["archive_path"]
	if gotPath == "" {
		t.Errorf("expected archive_path in ExtraData; got %+v", f.Result.ExtraData)
	}
	// Path should mention both the source filename and the inner entry.
	if !bytes.Contains([]byte(gotPath), []byte("config.env")) {
		t.Errorf("archive_path missing inner entry: %q", gotPath)
	}
}

// _ keeps the import set consistent if a downstream refactor stops
// using sources directly in this file.
var _ = sources.SourceFilesystem
