package engine

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

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
	s.Emit(mk("git-diff"))

	if got := len(rec.findings); got != 2 {
		t.Fatalf("expected 2 distinct labels to flow through; got %d", got)
	}
}

func TestDedupSuppressesGenericWhenVerifierWins(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	provider := mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1)
	provider.VerifierBacked = true
	generic := mkFinding(detectors.GenericHighEntropy, "AKIA0000000000000000", "/a.txt", 1)
	s.Emit(provider)
	s.Emit(generic)

	if got := len(rec.findings); got != 1 {
		t.Fatalf("generic should be suppressed by Verifier-backed peer: got %d", got)
	}
	if rec.findings[0].Detector != detectors.AWS {
		t.Fatalf("expected AWS finding to survive; got %v", rec.findings[0].Detector)
	}
}

func TestDedupKeepsGenericWhenNoVerifierPeer(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	generic := mkFinding(detectors.GenericHighEntropy, "Zm9vYmFyYmF6cXV4MTIzNDU=", "/a.txt", 1)
	s.Emit(generic)

	if got := len(rec.findings); got != 1 {
		t.Fatalf("lone generic finding must still emit: got %d", got)
	}
}

func TestDedupGenericDedupUnchanged(t *testing.T) {
	rec := &recordingSink{}
	s := NewDedup(rec)

	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/a.txt", 1))
	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/b.txt", 1))
	s.Emit(mkFinding(detectors.GenericHighEntropy, "hash-shaped-thing", "/a.txt", 1))

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

// helpers for GitCrossCommitDedup tests

func mkGitFinding(raw, file, commit string) Finding {
	return Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{DetectorType: detectors.AWS, Raw: []byte(raw)},
		Chunk: &sources.Chunk{
			SourceType: sources.SourceGit,
			SourceMetadata: sources.Metadata{
				Git: &sources.GitMeta{
					Repository: "repo",
					Commit:     commit,
					File:       file,
				},
			},
		},
	}
}

func TestGitCrossCommitDedup_CollapsesMultipleCommits(t *testing.T) {
	rec := &recordingSink{}
	s := NewGitCrossCommitDedup(rec)

	s.Emit(mkGitFinding("AKIA0000000000000000", "config.js", "abc1"))
	s.Emit(mkGitFinding("AKIA0000000000000000", "config.js", "abc2"))
	s.Emit(mkGitFinding("AKIA0000000000000000", "config.js", "abc3"))
	_ = s.Close()

	if got := len(rec.findings); got != 1 {
		t.Fatalf("want 1 finding (introducing commit), got %d", got)
	}
	if got := rec.findings[0].Chunk.SourceMetadata.Git.Commit; got != "abc1" {
		t.Errorf("want introducing commit abc1, got %s", got)
	}
	if got := rec.findings[0].Result.ExtraData["occurrence_count"]; got != "3" {
		t.Errorf("want occurrence_count=3, got %q", got)
	}
}

func TestGitCrossCommitDedup_KeepsDistinctFiles(t *testing.T) {
	rec := &recordingSink{}
	s := NewGitCrossCommitDedup(rec)

	s.Emit(mkGitFinding("AKIA0000000000000000", "a.js", "abc1"))
	s.Emit(mkGitFinding("AKIA0000000000000000", "b.js", "abc1"))
	_ = s.Close()

	if got := len(rec.findings); got != 2 {
		t.Fatalf("same secret in different files should not collapse: got %d", got)
	}
}

func TestGitCrossCommitDedup_KeepsDistinctSecrets(t *testing.T) {
	rec := &recordingSink{}
	s := NewGitCrossCommitDedup(rec)

	s.Emit(mkGitFinding("AKIA0000000000000000", "cfg.js", "abc1"))
	s.Emit(mkGitFinding("AKIA1111111111111111", "cfg.js", "abc1"))
	_ = s.Close()

	if got := len(rec.findings); got != 2 {
		t.Fatalf("distinct secrets should not collapse: got %d", got)
	}
}

func TestGitCrossCommitDedup_NoOccurrenceCountForSingle(t *testing.T) {
	rec := &recordingSink{}
	s := NewGitCrossCommitDedup(rec)

	s.Emit(mkGitFinding("AKIA0000000000000000", "cfg.js", "abc1"))
	_ = s.Close()

	if got := len(rec.findings); got != 1 {
		t.Fatalf("single finding must emit: got %d", got)
	}
	if _, ok := rec.findings[0].Result.ExtraData["occurrence_count"]; ok {
		t.Errorf("single occurrence should not add occurrence_count to ExtraData")
	}
}

func TestGitCrossCommitDedup_NonGitPassesThrough(t *testing.T) {
	rec := &recordingSink{}
	s := NewGitCrossCommitDedup(rec)

	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1))
	s.Emit(mkFinding(detectors.AWS, "AKIA0000000000000000", "/a.txt", 1))
	_ = s.Close()

	// Non-git findings pass through immediately without cross-commit dedup;
	// two identical filesystem findings should both reach the recording sink
	// (upstream NewDedup would normally collapse them, but here we bypass it).
	if got := len(rec.findings); got != 2 {
		t.Fatalf("non-git findings should pass through unfiltered: got %d", got)
	}
}
