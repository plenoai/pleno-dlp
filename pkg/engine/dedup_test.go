package engine

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
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

func TestDedupKey_DistinguishesStdinLabels(t *testing.T) {
	// Same secret arriving from two stdin invocations with different
	// labels (`git diff` vs `kubectl get secret`) must not dedup —
	// they're materially different scans, and collapsing them would
	// hide the second leak.
	rec := &recordingSink{}
	s := NewDedup(rec)

	mk := func(label string) Finding {
		return Finding{
			Detector: detectors.AWS,
			Result:   detectors.Result{Raw: []byte("AKIA0000000000000000")},
			Chunk: &sources.Chunk{
				SourceType: sources.SourceStdin,
				SourceMetadata: sources.Metadata{
					Stdin: &sources.StdinMeta{Label: label},
				},
			},
		}
	}
	s.Emit(mk("git-diff"))
	s.Emit(mk("k8s-secrets"))
	s.Emit(mk("git-diff")) // same as first → must dedup

	if got := len(rec.findings); got != 2 {
		t.Fatalf("expected 2 distinct labels to flow through; got %d", got)
	}
}

// TestDedupSuppressesGenericWhenVerifierWins covers the cross-detector
// collision rule: when a Verifier-backed provider detector and the
// generic high-entropy detector both fire on the same raw bytes at the
// same location, only the Verifier-backed finding propagates. Without
// this rule, every successful provider hit produces a shadow generic
// finding and inflates the dashboard.
func TestDedupSuppressesGenericWhenVerifierWins(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	provider := mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1)
	provider.VerifierBacked = true
	generic := mkFinding(detectors.GenericHighEntropy, "AKIA0000000000000000", "/a.txt", 1)
	// generic.VerifierBacked stays false — the whole point of generic
	// is that there's no upstream API to verify against.

	s.Emit(provider)
	s.Emit(generic)

	if got := len(rec.findings); got != 1 {
		t.Fatalf("generic should be suppressed by Verifier-backed peer: got %d", got)
	}
	if rec.findings[0].Detector != detectors.AWS {
		t.Fatalf("expected AWS finding to survive; got %v", rec.findings[0].Detector)
	}
}

// TestDedupKeepsGenericWhenNoVerifierPeer ensures the suppression is
// scoped to actual collisions. A generic finding alone at a location
// must still be reported — that's the whole reason the generic detector
// exists. This test also asserts the reverse-order case (generic
// arrives first, no Verifier peer ever shows up) doesn't silently
// suppress generic emissions.
func TestDedupKeepsGenericWhenNoVerifierPeer(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	generic := mkFinding(detectors.GenericHighEntropy, "Zm9vYmFyYmF6cXV4MTIzNDU=", "/a.txt", 1)
	s.Emit(generic)

	if got := len(rec.findings); got != 1 {
		t.Fatalf("lone generic finding must still emit: got %d", got)
	}
}

// TestDedupGenericDedupUnchanged verifies the pre-existing baseline:
// the same raw bytes hit by the generic detector at two distinct
// locations remain two separate findings. The Verifier-priority logic
// must not over-suppress within a single detector type.
func TestDedupGenericDedupUnchanged(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/a.txt", 1))
	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/b.txt", 1))
	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/a.txt", 1)) // dup

	if got := len(rec.findings); got != 2 {
		t.Fatalf("generic-on-generic dedup regressed: got %d, want 2", got)
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
