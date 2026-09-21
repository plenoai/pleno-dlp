package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// filesystemLazyCheckpointSource models the filesystem source after it has
// admitted a large file: the walk has candidate state, while the engine owns
// the later Open call. The CLI must retain the last durable checkpoint when
// that deferred open fails, then retry it on the next run.
type filesystemLazyCheckpointSource struct {
	fingerprint string
	candidate   json.RawMessage
	failOpen    bool
	previous    json.RawMessage
	calls       int
}

func (*filesystemLazyCheckpointSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

func (*filesystemLazyCheckpointSource) Type() sources.SourceType { return sources.SourceFilesystem }

func (s *filesystemLazyCheckpointSource) ResourceFingerprint(context.Context) (string, error) {
	return s.fingerprint, nil
}

func (s *filesystemLazyCheckpointSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = append(s.previous[:0], state...)
	return nil
}

func (s *filesystemLazyCheckpointSource) IncrementalState() json.RawMessage {
	return append(json.RawMessage(nil), s.candidate...)
}

func (s *filesystemLazyCheckpointSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	s.calls++
	failOpen := s.failOpen
	const body = "lazy checkpoint body\n"
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			if failOpen {
				return nil, nil, 0, errors.New("filesystem: deferred open failed")
			}
			return bytes.NewReader([]byte(body)), io.NopCloser(bytes.NewReader(nil)), int64(len(body)), nil
		},
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/fixture/lazy-checkpoint.txt", Line: 1},
		},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestRunScanCommon_LazyFilesystemOpenFailureRetainsDurableCheckpointForRetry(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanFilesystemCmd.SetContext(context.Background())

	var output bytes.Buffer
	scanFilesystemCmd.SetOut(&output)
	scanFilesystemCmd.SetErr(&output)
	t.Cleanup(func() {
		scanFilesystemCmd.SetOut(nil)
		scanFilesystemCmd.SetErr(nil)
		scanFilesystemCmd.SetContext(context.Background())
	})

	prior := json.RawMessage(`{"version":1,"files":{"/fixture/lazy-checkpoint.txt":{"size":20,"mode":384,"mod_time":1}}}`)
	baseline := &filesystemLazyCheckpointSource{
		fingerprint: "before",
		candidate:   prior,
	}
	if err := runScanCommon(scanFilesystemCmd, baseline, nil, "filesystem"); err != nil {
		t.Fatalf("baseline run: %v", err)
	}

	failed := &filesystemLazyCheckpointSource{
		fingerprint: "after",
		candidate:   json.RawMessage(`{"version":1,"files":{"/fixture/lazy-checkpoint.txt":{"size":21,"mode":384,"mod_time":2}}}`),
		failOpen:    true,
	}
	if err := runScanCommon(scanFilesystemCmd, failed, nil, "filesystem"); err == nil {
		t.Fatal("deferred filesystem open failure was accepted")
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	entry := onlyIncrementalEntry(t, state)
	if entry.ResourceFingerprint != "" || !sameJSON(entry.SourceState, prior) {
		t.Fatalf("failed lazy read advanced durable checkpoint: %+v, want prior source state with empty fingerprint", entry)
	}

	retry := &filesystemLazyCheckpointSource{
		fingerprint: "after",
		candidate:   json.RawMessage(`{"version":1,"files":{"/fixture/lazy-checkpoint.txt":{"size":21,"mode":384,"mod_time":2}}}`),
	}
	if err := runScanCommon(scanFilesystemCmd, retry, nil, "filesystem"); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	if retry.calls != 1 || !sameJSON(retry.previous, prior) {
		t.Fatalf("retry did not receive durable prior state: calls=%d previous=%q", retry.calls, retry.previous)
	}
	entry = onlyIncrementalEntry(t, mustLoadIncrementalState(t, scanOpts.incrementalState))
	if entry.ResourceFingerprint != "after" || !sameJSON(entry.SourceState, retry.candidate) {
		t.Fatalf("successful retry checkpoint = %+v, want updated source state", entry)
	}
}

func onlyIncrementalEntry(t *testing.T, state *incrementalStateFile) incrementalStateEntry {
	t.Helper()
	if len(state.Entries) != 1 {
		t.Fatalf("incremental entries=%d, want one", len(state.Entries))
	}
	for _, entry := range state.Entries {
		return entry
	}
	panic("unreachable")
}

func mustLoadIncrementalState(t *testing.T, path string) *incrementalStateFile {
	t.Helper()
	state, err := loadIncrementalState(path)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func sameJSON(a, b []byte) bool {
	var compactA, compactB bytes.Buffer
	if err := json.Compact(&compactA, a); err != nil {
		return false
	}
	if err := json.Compact(&compactB, b); err != nil {
		return false
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
}
