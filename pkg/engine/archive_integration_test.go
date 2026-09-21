package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type slowArchiveDetector struct {
	delay time.Duration
	calls atomic.Int32
}

func (*slowArchiveDetector) Type() detectors.DetectorType { return detectors.AWS }
func (*slowArchiveDetector) Keywords() []string           { return []string{"TRIGGER"} }
func (d *slowArchiveDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	d.calls.Add(1)
	time.Sleep(d.delay)
	if !bytes.Contains(data, []byte("TRIGGER")) {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: []byte("TRIGGER")}}, nil
}

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

func TestScanArchive_PausesExpansionBudgetDuringLeafScan(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"first.txt", "second.txt"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create %s: %v", name, err)
		}
		if _, err := w.Write([]byte("TRIGGER\n")); err != nil {
			t.Fatalf("zip Write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}

	det := &slowArchiveDetector{delay: 150 * time.Millisecond}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{det}, Options{Concurrency: 1}, sink)
	eng.resetFailures()
	eng.scanArchive(context.Background(), &sources.Chunk{SourceName: "bundle.zip", Data: buf.Bytes()}, 100*time.Millisecond)
	if err := eng.takeFailures(); err != nil {
		t.Fatalf("slow leaf scan should not consume expansion budget: %v", err)
	}
	if got := det.calls.Load(); got != 2 {
		t.Fatalf("detector calls = %d, want both archive leaves scanned", got)
	}
	findings := sink.Findings()
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want one per archive leaf", len(findings))
	}
	for _, finding := range findings {
		if path := finding.Result.ExtraData["archive_path"]; !strings.Contains(path, "!") {
			t.Errorf("archive_path = %q, want inner entry path", path)
		}
	}
}

func TestScanArchive_ExpiredBudgetReportsCoverageFailure(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("payload.txt")
	if err != nil {
		t.Fatalf("zip Create: %v", err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatalf("zip Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}

	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &engineRecordingSink{})
	eng.resetFailures()
	eng.scanArchive(context.Background(), &sources.Chunk{SourceName: "expired.zip", Data: buf.Bytes()}, -time.Second)
	err = eng.takeFailures()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("coverage error = %v, want context deadline exceeded", err)
	}
}

type budgetReader struct {
	started chan struct{}
	release chan struct{}
	reads   atomic.Int32
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if r.reads.Add(1) == 1 {
		close(r.started)
		<-r.release
	}
	if r.reads.Load() <= 2 {
		p[0] = 0
		return 1, nil
	}
	return 0, io.EOF
}

func TestScanArchiveReaderStopsAfterBudgetContext(t *testing.T) {
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &engineRecordingSink{})
	eng.resetFailures()
	reader := &budgetReader{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		eng.scanArchiveReader(context.Background(), &sources.Chunk{SourceName: "budget.zip"}, reader, 2, 10*time.Millisecond)
		close(done)
	}()
	select {
	case <-reader.started:
	case <-time.After(100 * time.Millisecond):
		close(reader.release)
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("archive reader cleanup timed out")
		}
		t.Fatal("archive reader did not start")
	}
	time.Sleep(25 * time.Millisecond)
	close(reader.release)
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("archive reader did not stop after budget")
	}
	if got := reader.reads.Load(); got != 1 {
		t.Fatalf("reader calls = %d, want one before deadline", got)
	}
	if err := eng.takeFailures(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("coverage error = %v, want context deadline exceeded", err)
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
