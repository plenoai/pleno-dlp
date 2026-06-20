package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestSpoolSink_WritesVerifiedOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.jsonl")

	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	s, err := newSpoolSink(captured, []detectors.Detector{det}, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("newSpoolSink: %v", err)
	}

	s.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))
	s.Emit(engineFinding(detectors.GitHub, false, "ghp_unverified"))

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rev.calls != 0 {
		t.Errorf("spool path must not call the revoker, got %d calls", rev.calls)
	}
	if got := len(captured.findings); got != 2 {
		t.Errorf("expected 2 findings forwarded downstream, got %d", got)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one spool line for the verified finding, got %d: %q", len(lines), lines)
	}
	var rec spoolRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode spool line: %v", err)
	}
	if rec.Version != spoolRecordVersion {
		t.Errorf("spool version=%d, want %d", rec.Version, spoolRecordVersion)
	}
	if rec.Detector != detectors.GitHub.String() {
		t.Errorf("spool detector=%q, want %q", rec.Detector, detectors.GitHub.String())
	}
	secret, derr := base64.StdEncoding.DecodeString(rec.SecretB64)
	if derr != nil {
		t.Fatalf("decode secret_b64: %v", derr)
	}
	if string(secret) != "ghp_verified" {
		t.Errorf("decoded secret=%q, want %q", secret, "ghp_verified")
	}
	if s.queued.Load() != 1 || s.skippedNoRv.Load() != 0 || s.writeErrs.Load() != 0 {
		t.Errorf("counters queued=%d skipped=%d errs=%d, want 1/0/0",
			s.queued.Load(), s.skippedNoRv.Load(), s.writeErrs.Load())
	}
}

func TestSpoolSink_SkipsDetectorsWithoutRevoker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.jsonl")

	captured := &captureSink{}
	s, err := newSpoolSink(captured, []detectors.Detector{stubDet{t: detectors.AWS}}, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("newSpoolSink: %v", err)
	}

	s.Emit(engineFinding(detectors.AWS, true, "AKIA_no_revoker"))
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("spool must stay empty when no Revoker is registered; got: %q", body)
	}
	if s.queued.Load() != 0 || s.skippedNoRv.Load() != 1 {
		t.Errorf("counters queued=%d skipped=%d, want 0/1", s.queued.Load(), s.skippedNoRv.Load())
	}
}

func TestSpoolSink_FileIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix-mode assertion is meaningless on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.jsonl")

	det := fakeDetectorWithRevoker{Revoker: &fakeRevoker{}}
	s, err := newSpoolSink(&captureSink{}, []detectors.Detector{det}, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("newSpoolSink: %v", err)
	}
	_ = s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat spool: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("spool perm=%o, want 0600 (raw secret file must not be world/group readable)", got)
	}
}

func TestSpoolSink_TruncatesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spool.jsonl")
	if err := os.WriteFile(path, []byte("STALE_PREVIOUS_RUN_LINE\n"), 0o600); err != nil {
		t.Fatalf("seed stale spool: %v", err)
	}

	det := fakeDetectorWithRevoker{Revoker: &fakeRevoker{}}
	s, err := newSpoolSink(&captureSink{}, []detectors.Detector{det}, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("newSpoolSink: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if strings.Contains(string(body), "STALE_PREVIOUS_RUN_LINE") {
		t.Errorf("spool must truncate on open to avoid stale revoke replay; got: %q", body)
	}
}
