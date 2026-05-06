package engine

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-secret-scanner/pkg/detectors"
	"github.com/plenoai/pleno-secret-scanner/pkg/sources"
)

// recordingSink captures every Emit so tests can assert on what slipped
// through dedup. Concurrency-safe so race-detector tests can hammer it.
type recordingSink struct {
	mu       sync.Mutex
	findings []Finding
	closed   atomic.Bool
}

func (r *recordingSink) Emit(f Finding) {
	r.mu.Lock()
	r.findings = append(r.findings, f)
	r.mu.Unlock()
}

func (r *recordingSink) Close() error {
	r.closed.Store(true)
	return nil
}

func mkFinding(det detectors.DetectorType, raw, path string, line int) Finding {
	return Finding{
		Detector: det,
		Result:   detectors.Result{DetectorType: det, Raw: []byte(raw)},
		Chunk: &sources.Chunk{
			SourceType: sources.SourceFilesystem,
			SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{Path: path, Line: line},
			},
		},
	}
}

func TestDedupSuppressesIdenticalFindings(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	f := mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1)
	s.Emit(f)
	s.Emit(f)
	s.Emit(f)

	if got := len(rec.findings); got != 1 {
		t.Fatalf("want 1 forwarded, got %d", got)
	}
}

func TestDedupKeepsDistinctLocations(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1))
	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/b.txt", 1))
	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 2))

	if got := len(rec.findings); got != 3 {
		t.Fatalf("distinct locations should not dedup: got %d", got)
	}
}

func TestDedupKeepsDistinctSecrets(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1))
	s.Emit(mkFinding(detectors.AWS, "AKIA1111111111111111", "/a.txt", 1))

	if got := len(rec.findings); got != 2 {
		t.Fatalf("distinct secrets should not dedup: got %d", got)
	}
}

func TestDedupKeepsDistinctDetectors(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	s.Emit(mkFinding(detectors.AWS, "shared", "/a.txt", 1))
	s.Emit(mkFinding(detectors.GitHub, "shared", "/a.txt", 1))

	if got := len(rec.findings); got != 2 {
		t.Fatalf("distinct detectors should not dedup: got %d", got)
	}
}

func TestDedupCloseDelegates(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !rec.closed.Load() {
		t.Errorf("inner.Close not called")
	}
}

func TestDedupConcurrent(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	const workers = 32
	const perWorker = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1))
			}
		}()
	}
	wg.Wait()

	if got := len(rec.findings); got != 1 {
		t.Fatalf("concurrent identical emits should dedup to 1: got %d", got)
	}
}
