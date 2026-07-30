package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"strings"
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
	eng := NewWithDetectors(
		[]detectors.Detector{fakeDetector{needle: akia}},
		Options{Concurrency: 1},
		sink,
	)

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

func TestArchiveRootNameUsesS3ObjectKey(t *testing.T) {
	chunk := &sources.Chunk{
		SourceName: "cli",
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: "example-bucket", Key: "archives/bundle.zip"},
		},
	}
	if got, want := archiveRootName(chunk), "archives/bundle.zip"; got != want {
		t.Fatalf("archiveRootName = %q, want %q", got, want)
	}
}

func TestArchiveCoverageFailureRedactsS3KeyAndEntry(t *testing.T) {
	const (
		hostileKey   = "credential-like-object-key.zip"
		hostileEntry = "credential-like-entry.txt"
	)
	marker := []byte("archive-entry-marker")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: hostileEntry, Method: zip.Store})
	if err != nil {
		t.Fatalf("zip CreateHeader: %v", err)
	}
	if _, err := w.Write(marker); err != nil {
		t.Fatalf("zip Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	payload := append([]byte(nil), buf.Bytes()...)
	markerOffset := bytes.Index(payload, marker)
	if markerOffset < 0 {
		t.Fatal("zip payload did not contain the stored marker")
	}
	payload[markerOffset] ^= 0xff // Keep headers valid while forcing a CRC failure.

	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &recordingSink{})
	eng.resetFailures()
	eng.scanChunk(context.Background(), &sources.Chunk{
		SourceName: "cli",
		Data:       payload,
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: "example-bucket", Key: hostileKey},
		},
	})
	err = eng.takeFailures()
	var degraded *DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 {
		t.Fatalf("error = %#v, want one archive coverage failure", err)
	}
	rendered := err.Error()
	if strings.Contains(rendered, hostileKey) || strings.Contains(rendered, hostileEntry) {
		t.Fatalf("coverage error exposed S3 archive provenance: %q", rendered)
	}
	if got := degraded.Failures[0].Source; !strings.HasPrefix(got, "s3-object-sha256:") {
		t.Fatalf("failure source = %q, want opaque S3 locator", got)
	}
	if !errors.Is(err, zip.ErrChecksum) {
		t.Fatal("archive error redaction did not preserve the original cause")
	}
}

// _ keeps the import set consistent if a downstream refactor stops
// using sources directly in this file.
var _ = sources.SourceFilesystem
