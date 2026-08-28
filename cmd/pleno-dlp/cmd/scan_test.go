package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	archivepkg "github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/audit"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

type degradedFindingSource struct{}

type allowedArchiveSource struct {
	next     json.RawMessage
	previous string
}

func (*allowedArchiveSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (*allowedArchiveSource) Type() sources.SourceType { return sources.SourceGitHub }
func (*allowedArchiveSource) ResourceFingerprint(context.Context) (string, error) {
	return "changed", nil
}
func (s *allowedArchiveSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state)
	return nil
}
func (s *allowedArchiveSource) IncrementalState() json.RawMessage { return s.next }
func (*allowedArchiveSource) Chunks(context.Context, chan<- *sources.Chunk) error {
	partial := &archivepkg.PartialError{Kind: "corrupt-archive", Entry: "model.pt", Err: io.ErrUnexpectedEOF}
	archiveFailure := &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureArchive: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureArchive, Source: "model.pt", Err: partial}},
	}
	nested := &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "tree-diff", Err: fmt.Errorf("expand archive: %w", archiveFailure)}},
	}
	return &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "repository-history:acme/model", Err: nested}},
	}
}

type allowedRepoWalkTimeoutSource struct{ allowedArchiveSource }

func (*allowedRepoWalkTimeoutSource) Chunks(context.Context, chan<- *sources.Chunk) error {
	timeout := fmt.Errorf("github: repository walk acme/slow exceeded 2h0m0s: %w", context.DeadlineExceeded)
	return &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "repository-history:acme/slow", Err: timeout}},
	}
}

type retryAfterDegradedSource struct {
	degraded    bool
	fatal       bool
	partialSafe bool
	fingerprint string
	previous    string
	calls       int
	flush       sources.IncrementalFlushFunc
}

type archiveCheckpointSource struct {
	data     []byte
	next     json.RawMessage
	previous string
	calls    int
}

func (*archiveCheckpointSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (*archiveCheckpointSource) Type() sources.SourceType { return sources.SourceS3 }
func (*archiveCheckpointSource) ResourceFingerprint(context.Context) (string, error) {
	return "", nil
}
func (s *archiveCheckpointSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state)
	return nil
}
func (s *archiveCheckpointSource) IncrementalState() json.RawMessage { return s.next }
func (s *archiveCheckpointSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	s.calls++
	if len(s.data) == 0 {
		return nil
	}
	select {
	case ch <- &sources.Chunk{
		SourceType: sources.SourceS3,
		SourceName: "cli",
		Data:       s.data,
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: "example-bucket", Key: "broken.zip"},
		},
	}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*retryAfterDegradedSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (*retryAfterDegradedSource) Type() sources.SourceType { return sources.SourceGitHub }
func (s *retryAfterDegradedSource) ResourceFingerprint(context.Context) (string, error) {
	if s.fingerprint != "" {
		return s.fingerprint, nil
	}
	return "stable-resources", nil
}
func (s *retryAfterDegradedSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state)
	return nil
}
func (s *retryAfterDegradedSource) IncrementalState() json.RawMessage {
	if s.degraded || s.fatal {
		return json.RawMessage(`"partial"`)
	}
	return json.RawMessage(`"complete"`)
}
func (s *retryAfterDegradedSource) PartialIncrementalStateSafe() bool { return s.partialSafe }
func (s *retryAfterDegradedSource) SetIncrementalFlush(flush sources.IncrementalFlushFunc) {
	s.flush = flush
}
func (s *retryAfterDegradedSource) Chunks(context.Context, chan<- *sources.Chunk) error {
	s.calls++
	if (s.degraded || s.fatal) && s.flush != nil {
		if err := s.flush(json.RawMessage(`"partial"`)); err != nil {
			return err
		}
	}
	if s.fatal {
		return errors.New("injected fatal source failure")
	}
	if !s.degraded {
		return nil
	}
	return &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "repository-history:acme/timed-out", Err: context.DeadlineExceeded}},
	}
}

func (degradedFindingSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

type incrementalCollaborationSource struct{ previous bool }

func (*incrementalCollaborationSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

type incrementalWikiSource struct{ previous bool }

func (*incrementalWikiSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

type incrementalGistSource struct{ previous bool }

func (*incrementalGistSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (*incrementalGistSource) Type() sources.SourceType                            { return sources.SourceGitHub }
func (*incrementalGistSource) ResourceFingerprint(context.Context) (string, error) { return "", nil }
func (s *incrementalGistSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state) == `"done"`
	return nil
}
func (*incrementalGistSource) IncrementalState() json.RawMessage { return json.RawMessage(`"done"`) }
func (s *incrementalGistSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if s.previous {
		return nil
	}
	c := &sources.Chunk{SourceType: sources.SourceGitHub, Data: []byte("token=github_pat_11AAABBB_abcdefghijklmnopqrstuvwxyz0123456789"), SourceMetadata: sources.Metadata{GitHub: &sources.GitHubMeta{Repository: "gist:abc123", Owner: "alice", Repo: "abc123", Visibility: "secret", Link: "https://gist.github.com/abc123", File: "config.env", Path: "config.env", Entity: "gist", Part: "content"}}}
	select {
	case ch <- c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*incrementalWikiSource) Type() sources.SourceType                            { return sources.SourceGitHub }
func (*incrementalWikiSource) ResourceFingerprint(context.Context) (string, error) { return "", nil }
func (s *incrementalWikiSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state) == `"done"`
	return nil
}
func (*incrementalWikiSource) IncrementalState() json.RawMessage { return json.RawMessage(`"done"`) }
func (s *incrementalWikiSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if s.previous {
		return nil
	}
	chunk := &sources.Chunk{SourceType: sources.SourceGitHub, Data: []byte("token=github_pat_11AAABBB_abcdefghijklmnopqrstuvwxyz0123456789"), SourceMetadata: sources.Metadata{GitHub: &sources.GitHubMeta{
		Repository: "acme/repo", Owner: "acme", Repo: "repo", Visibility: "private", Link: "https://github.com/acme/repo/wiki/Runbook",
		File: "Runbook.md", Path: "Runbook.md", Entity: "wiki", Part: "page",
	}}}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*incrementalCollaborationSource) Type() sources.SourceType { return sources.SourceGitHub }
func (*incrementalCollaborationSource) ResourceFingerprint(context.Context) (string, error) {
	return "", nil
}
func (s *incrementalCollaborationSource) SetIncrementalState(state json.RawMessage) error {
	s.previous = string(state) == `"done"`
	return nil
}
func (*incrementalCollaborationSource) IncrementalState() json.RawMessage {
	return json.RawMessage(`"done"`)
}
func (s *incrementalCollaborationSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if s.previous {
		return nil
	}
	for _, item := range []struct {
		entity, link, body string
		number             int
	}{
		{"issue", "https://github.com/acme/repo/issues/7", "token=github_pat_11AAABBB_abcdefghijklmnopqrstuvwxyz0123456789", 7},
		{"pull_request", "https://github.com/acme/repo/pull/8", "token=github_pat_11CCCDDD_abcdefghijklmnopqrstuvwxyz9876543210", 8},
	} {
		chunk := &sources.Chunk{SourceType: sources.SourceGitHub, Data: []byte(item.body), SourceMetadata: sources.Metadata{GitHub: &sources.GitHubMeta{
			Repository: "acme/repo", Owner: "acme", Repo: "repo", Visibility: "private", Link: item.link,
			File: fmt.Sprintf("%s:%d:body", item.entity, item.number), Path: fmt.Sprintf("%s:%d:body", item.entity, item.number), Entity: item.entity, Number: item.number, Part: "body",
		}}}
		select {
		case ch <- chunk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (degradedFindingSource) Type() sources.SourceType { return sources.SourceGitHub }
func (degradedFindingSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	select {
	case ch <- &sources.Chunk{SourceType: sources.SourceGitHub, Data: []byte("token=github_pat_11AAABBB_abcdefghijklmnopqrstuvwxyz0123456789")}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "repository-history:acme/broken", Err: errors.New("clone failed")}},
	}
}

func TestScanHelp(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--help"})

	if err := Root.Execute(); err != nil {
		t.Fatalf("scan --help: %v", err)
	}

	got := out.String()
	for _, want := range []string{"--format", "--concurrency", "--cpu-profile", "scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("help missing %q in:\n%s", want, got)
		}
	}
}

func TestScanCPUProfile(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "scan.cpu.pprof")
	if err := os.WriteFile(profile, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--no-verify", "--quiet", "--cpu-profile", profile, "filesystem", dir})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan with CPU profile: %v\n%s", err, out.String())
	}
	info, err := os.Stat(profile)
	if err != nil {
		t.Fatalf("CPU profile missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("CPU profile is empty")
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CPU profile mode = %o, want 600", info.Mode().Perm())
	}
}

func TestScanCPUProfileInvalidInvocationPreservesExistingFile(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	profile := filepath.Join(t.TempDir(), "scan.cpu.pprof")
	want := []byte("existing-profile")
	if err := os.WriteFile(profile, want, 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--cpu-profile", profile, "--no-verify", "--only-verified", "filesystem", dir})
	if err := Root.Execute(); err == nil {
		t.Fatal("invalid verification flags were accepted")
	}
	got, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("invalid invocation changed profile: got %q want %q", got, want)
	}
	info, err := os.Stat(profile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("invalid invocation changed profile mode to %o", info.Mode().Perm())
	}
}

func TestScanCPUProfileLateValidationPreservesExistingFile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(t *testing.T, dir, profile string) []string
	}{
		{
			name: "invalid output format",
			configure: func(_ *testing.T, dir, profile string) []string {
				return []string{"scan", "--no-verify", "--cpu-profile", profile, "--format", "invalid", "filesystem", dir}
			},
		},
		{
			name: "corrupt incremental state",
			configure: func(t *testing.T, dir, profile string) []string {
				state := filepath.Join(t.TempDir(), "state.json")
				if err := os.WriteFile(state, []byte("not-json"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"scan", "--no-verify", "--cpu-profile", profile, "--incremental", "--incremental-state", state, "filesystem", dir}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCommandFlags(t)
			dir := t.TempDir()
			profile := filepath.Join(t.TempDir(), "scan.cpu.pprof")
			want := []byte("existing-profile")
			if err := os.WriteFile(profile, want, 0o640); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			Root.SetOut(&out)
			Root.SetErr(&out)
			Root.SetArgs(tc.configure(t, dir, profile))
			if err := Root.Execute(); err == nil {
				t.Fatal("invalid invocation was accepted")
			}
			got, err := os.ReadFile(profile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("invalid invocation changed profile: got %q want %q", got, want)
			}
			info, err := os.Stat(profile)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Fatalf("invalid invocation changed profile mode to %o", info.Mode().Perm())
			}
		})
	}
}

func TestScanCPUProfileStartFailurePreservesExistingFile(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	profileDir := t.TempDir()
	profile := filepath.Join(profileDir, "scan.cpu.pprof")
	want := []byte("existing-profile")
	if err := os.WriteFile(profile, want, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(io.Discard); err != nil {
		t.Fatalf("start controlling CPU profile: %v", err)
	}
	profiling := true
	defer func() {
		if profiling {
			pprof.StopCPUProfile()
		}
	}()

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--no-verify", "--quiet", "--cpu-profile", profile, "filesystem", dir})
	err := Root.Execute()
	pprof.StopCPUProfile()
	profiling = false
	if err == nil || !strings.Contains(err.Error(), "start CPU profile") {
		t.Fatalf("scan error = %v, want CPU profile start failure", err)
	}
	got, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("profile start failure changed target: got %q want %q", got, want)
	}
	info, err := os.Stat(profile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("profile start failure changed target mode to %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(profile) {
		t.Fatalf("profile start failure left temporary files: %v", entries)
	}
}

func TestScanVerifyFlagRemoved(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--verify", "--help"})

	err := Root.Execute()
	if err == nil {
		t.Fatal("--verify must be rejected; verification is default-on")
	}
	if !strings.Contains(err.Error(), "unknown flag: --verify") {
		t.Fatalf("error must reject --verify: %v", err)
	}
}

func TestScanFilesystemRequiresPath(t *testing.T) {
	if err := scanFilesystemCmd.Args(scanFilesystemCmd, []string{}); err == nil {
		t.Errorf("expected error when no path given to scan filesystem")
	}
}

func TestScanFilesystem_CorruptArchiveReturnsCoverageError(t *testing.T) {
	resetCommandFlags(t)
	path := filepath.Join(t.TempDir(), "broken.zip")
	if err := os.WriteFile(path, []byte{'P', 'K', 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "filesystem", path, "--no-verify", "--quiet"})
	err := Root.Execute()
	if err == nil {
		t.Fatal("incomplete archive coverage must produce a non-zero CLI result")
	}
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("error = %v, want wrapped engine.DegradedError", err)
	}
	if !strings.Contains(err.Error(), "scan coverage incomplete") || !strings.Contains(err.Error(), "archive") {
		t.Fatalf("CLI error must explain incomplete archive coverage: %v", err)
	}
}

func TestRunScanCommonDegradedSourcePreservesFindingsAndReturnsTypedError(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify = true
	scanOpts.quiet = true
	scanOpts.format = "json"
	var out, stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	scanGitHubCmd.SetContext(context.Background())
	err := runScanCommon(scanGitHubCmd, degradedFindingSource{}, nil, "github")
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("error = %v, want typed source degradation", err)
	}
	if out.Len() == 0 || !strings.Contains(out.String(), "secret_hash") {
		t.Fatalf("successful-unit finding was discarded: %s", out.String())
	}
	if !strings.Contains(stderr.String(), "coverage: status=degraded failures=1 source=1") {
		t.Fatalf("missing machine-readable coverage status: %s", stderr.String())
	}
}

func TestRunScanCommonDegradedIncrementalRunPreservesPriorCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	baseline := &retryAfterDegradedSource{fingerprint: "before"}
	if err := runScanCommon(scanGitHubCmd, baseline, nil, "github-timeout-retry"); err != nil {
		t.Fatalf("baseline run: %v", err)
	}

	first := &retryAfterDegradedSource{degraded: true, fingerprint: "after"}
	err := runScanCommon(scanGitHubCmd, first, nil, "github-timeout-retry")
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || first.calls != 1 {
		t.Fatalf("first run calls=%d err=%v, want one degraded walk", first.calls, err)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Entries) != 1 {
		t.Fatalf("first run entries=%d, want 1", len(state.Entries))
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "" || string(entry.SourceState) != `"complete"` {
			t.Fatalf("degraded checkpoint = %+v, want empty fingerprint and prior complete source state", entry)
		}
	}

	second := &retryAfterDegradedSource{fingerprint: "after"}
	if err := runScanCommon(scanGitHubCmd, second, nil, "github-timeout-retry"); err != nil {
		t.Fatalf("retry run: %v", err)
	}
	if second.calls != 1 || second.previous != `"complete"` {
		t.Fatalf("retry fast-skipped unfinished resource: calls=%d previous=%q", second.calls, second.previous)
	}
	state, err = loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "after" || string(entry.SourceState) != `"complete"` {
			t.Fatalf("completed checkpoint = %+v", entry)
		}
	}
}

func TestRunScanCommonPublishesSafePartialRepositoryCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubOpts.publishPartialRepositoryState = true
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	src := &retryAfterDegradedSource{degraded: true, partialSafe: true, fingerprint: "after"}
	if err := runScanCommon(scanGitHubCmd, src, nil, "github"); err != nil {
		t.Fatalf("partial run: %v", err)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Entries) != 1 {
		t.Fatalf("partial run entries=%d, want 1", len(state.Entries))
	}
	var entry incrementalStateEntry
	for _, candidate := range state.Entries {
		entry = candidate
	}
	if entry.ResourceFingerprint != "" || string(entry.SourceState) != `"partial"` {
		t.Fatalf("partial checkpoint = %+v", entry)
	}
	if !strings.Contains(out.String(), "partial-repository-state=1 checkpoint=failed-repositories-retained") {
		t.Fatalf("missing partial checkpoint diagnostic: %s", out.String())
	}
}

func TestGitHubPartialRepositoryStateRejectsDetectorFailure(t *testing.T) {
	coverage := &engine.DegradedError{
		Total:    1,
		Counts:   map[engine.FailureKind]int{engine.FailureDetector: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureDetector, Source: "fixture", Err: errors.New("detector failure")}},
	}
	src := &retryAfterDegradedSource{partialSafe: true}
	if githubPartialRepositoryStateSafe(coverage, src) {
		t.Fatal("detector failure must not publish partial repository state")
	}
}

func TestLargestGitHubIncrementalEntrySelectsMostRepositoryHistory(t *testing.T) {
	entries := map[string]incrementalStateEntry{
		"github:small": {
			UpdatedAt:   "small",
			SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{}}}}`),
		},
		"github:largest": {
			UpdatedAt:   "largest",
			SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{},"acme/two":{}}}}`),
		},
		"github:old-version": {
			UpdatedAt:   "old-version",
			SourceState: json.RawMessage(`{"version":2,"surfaces":{"repository-history":{"acme/one":{},"acme/two":{},"acme/three":{}}}}`),
		},
		"filesystem:unrelated": {
			UpdatedAt:   "unrelated",
			SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{},"acme/two":{},"acme/three":{}}}}`),
		},
	}

	got, found, err := largestGitHubIncrementalEntry(entries)
	if err != nil {
		t.Fatal(err)
	}
	if !found || got.UpdatedAt != "largest" {
		t.Fatalf("selected entry = (%q, %v), want largest", got.UpdatedAt, found)
	}
}

func TestLargestGitHubIncrementalEntryRejectsAmbiguousLargest(t *testing.T) {
	entries := map[string]incrementalStateEntry{
		"github:first": {
			SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{},"acme/two":{}}}}`),
		},
		"github:second": {
			SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{},"acme/other":{}}}}`),
		},
	}

	if _, _, err := largestGitHubIncrementalEntry(entries); err == nil {
		t.Fatal("expected ambiguous migration candidates to fail closed")
	}
}

func TestLargestGitHubIncrementalEntryIgnoresEmptyAndInvalidState(t *testing.T) {
	entries := map[string]incrementalStateEntry{
		"github:empty":   {SourceState: json.RawMessage(`{"version":3,"surfaces":{"repository-history":{}}}`)},
		"github:invalid": {SourceState: json.RawMessage(`not-json`)},
	}

	if _, found, err := largestGitHubIncrementalEntry(entries); err != nil || found {
		t.Fatalf("empty migration result = (%v, %v), want no candidate", found, err)
	}
}

func TestPrepareIncrementalMigratesLargestGitHubSourceState(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.incremental, scanOpts.quiet = true, true
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	want := json.RawMessage(`{"version":3,"surfaces":{"repository-history":{"acme/one":{},"acme/two":{}}}}`)
	state := &incrementalStateFile{
		Version: 1,
		Entries: map[string]incrementalStateEntry{
			"github:legacy": {SourceState: want},
		},
	}
	if err := saveIncrementalState(scanOpts.incrementalState, state); err != nil {
		t.Fatal(err)
	}
	src := &retryAfterDegradedSource{fingerprint: "changed"}

	key, entry, loaded, err := prepareIncremental(context.Background(), "github", []byte(`{}`), src)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || entry != nil || loaded == nil {
		t.Fatalf("prepare result = (%q, %#v, %#v), want pending migrated scan", key, entry, loaded)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(src.previous)); err != nil {
		t.Fatal(err)
	}
	if compact.String() != string(want) {
		t.Fatalf("configured source state = %s, want migrated state", src.previous)
	}
}

func TestRunScanCommonArchiveFailureRestoresPriorCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	baseline := &archiveCheckpointSource{next: json.RawMessage(`"prior-complete"`)}
	if err := runScanCommon(scanGitHubCmd, baseline, nil, "s3-archive-checkpoint"); err != nil {
		t.Fatalf("baseline run: %v", err)
	}

	failed := &archiveCheckpointSource{
		data: []byte{'P', 'K', 3, 4},
		next: json.RawMessage(`"archive-emitted"`),
	}
	err := runScanCommon(scanGitHubCmd, failed, nil, "s3-archive-checkpoint")
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Counts[engine.FailureArchive] != 1 {
		t.Fatalf("archive run error = %v, want archive coverage degradation", err)
	}
	if failed.calls != 1 || failed.previous != `"prior-complete"` {
		t.Fatalf("archive run calls=%d previous=%q, want prior checkpoint and one attempt", failed.calls, failed.previous)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "" || string(entry.SourceState) != `"prior-complete"` {
			t.Fatalf("archive failure advanced checkpoint = %+v, want prior complete state", entry)
		}
	}
}

func TestRunScanCommonAllowedCorruptArchiveRetainsPartialCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubOpts.allowCorruptArchives = true
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	failed := &allowedArchiveSource{next: json.RawMessage(`"partial-progress"`)}
	if err := runScanCommon(scanGitHubCmd, failed, nil, "github"); err != nil {
		t.Fatalf("allowed corrupt archive run: %v", err)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "" || string(entry.SourceState) != `"partial-progress"` {
			t.Fatalf("partial checkpoint = %+v", entry)
		}
	}
	if !strings.Contains(out.String(), "accepted-corrupt-archives=1") {
		t.Fatalf("missing accepted coverage diagnostic: %s", out.String())
	}
}

func TestRunScanCommonAllowedRepoWalkTimeoutRetainsPartialCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubOpts.allowRepoWalkTimeouts = true
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	timedOut := &allowedRepoWalkTimeoutSource{allowedArchiveSource{next: json.RawMessage(`"partial-progress"`)}}
	if err := runScanCommon(scanGitHubCmd, timedOut, nil, "github"); err != nil {
		t.Fatalf("allowed repository timeout run: %v", err)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "" || string(entry.SourceState) != `"partial-progress"` {
			t.Fatalf("partial checkpoint = %+v", entry)
		}
	}
	if !strings.Contains(out.String(), "accepted-repo-walk-timeouts=1") {
		t.Fatalf("missing accepted timeout diagnostic: %s", out.String())
	}
}

func TestRepositoryWalkTimeoutFailureRejectsGenericDeadline(t *testing.T) {
	for _, failure := range []engine.ScanFailure{
		{Kind: engine.FailureSource, Source: "repository-history:acme/slow", Err: context.DeadlineExceeded},
		{Kind: engine.FailureSource, Source: "repository-history:acme/slow", Err: fmt.Errorf("provider timeout: %w", context.DeadlineExceeded)},
		{Kind: engine.FailureSource, Source: "collaboration:acme/slow", Err: fmt.Errorf("github: repository walk acme/slow exceeded 2h0m0s: %w", context.DeadlineExceeded)},
	} {
		if repositoryWalkTimeoutFailure(failure) {
			t.Fatalf("generic deadline accepted: %+v", failure)
		}
	}
}

func TestAcceptedGitHubCoverageAllowsExplicitMixedRetryableFailures(t *testing.T) {
	partial := &archivepkg.PartialError{Kind: "corrupt-entry", Entry: "broken.tar", Err: io.ErrUnexpectedEOF}
	timeout := fmt.Errorf("github: repository walk acme/slow exceeded 2h0m0s: %w", context.DeadlineExceeded)
	coverage := &engine.DegradedError{
		Total:  2,
		Counts: map[engine.FailureKind]int{engine.FailureArchive: 1, engine.FailureSource: 1},
		Failures: []engine.ScanFailure{
			{Kind: engine.FailureArchive, Source: "broken.tar", Err: partial},
			{Kind: engine.FailureSource, Source: "repository-history:acme/slow", Err: timeout},
		},
	}
	accepted, corruptArchives, repoWalkTimeouts := acceptedGitHubCoverage(coverage, true, true)
	if !accepted || corruptArchives != 1 || repoWalkTimeouts != 1 {
		t.Fatalf("mixed coverage = (%v, %d, %d), want (true, 1, 1)", accepted, corruptArchives, repoWalkTimeouts)
	}
}

func TestAcceptedGitHubCoverageRejectsImmutableHistoryPolicyGaps(t *testing.T) {
	corrupt := &archivepkg.PartialError{Kind: "corrupt-archive", Entry: "broken.zip", Err: io.ErrUnexpectedEOF}
	maxDepth := &archivepkg.PartialError{Kind: "max-depth", Entry: "nested.zip", Err: errors.New("depth exceeds 3")}
	invalidPath := &archivepkg.PartialError{Kind: "invalid-tree-path", Entry: "redacted", Err: errors.New("Git tree path contains a control character")}
	nested := &engine.DegradedError{
		Total:  3,
		Counts: map[engine.FailureKind]int{engine.FailureSource: 3},
		Failures: []engine.ScanFailure{
			{Kind: engine.FailureSource, Err: fmt.Errorf("git archive: %w", corrupt)},
			{Kind: engine.FailureSource, Err: fmt.Errorf("git archive: %w", maxDepth)},
			{Kind: engine.FailureSource, Err: fmt.Errorf("git tree: %w", invalidPath)},
		},
	}
	coverage := &engine.DegradedError{
		Total:    1,
		Counts:   map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureSource, Source: "repository-history:acme/repo", Err: nested}},
	}
	if accepted, _, _ := acceptedGitHubCoverage(coverage, true, false); accepted {
		t.Fatal("immutable history gap was accepted")
	}
	coverage.Failures[0].Err = errors.New(`to: invalid path "untyped": contains control character`)
	if accepted, _, _ := acceptedGitHubCoverage(coverage, true, false); accepted {
		t.Fatal("untyped lookalike invalid-path error was accepted")
	}
}

func TestCorruptArchiveCoverageOnlyRejectsOtherPartialKinds(t *testing.T) {
	partial := &archivepkg.PartialError{Kind: "budget", Entry: "large.zip", Err: context.DeadlineExceeded}
	coverage := &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureArchive: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureArchive, Source: "large.zip", Err: partial}},
	}
	if corruptArchiveCoverageOnly(coverage) {
		t.Fatal("budget partial error must remain fatal")
	}
}

func TestCorruptArchiveCoverageOnlyAcceptsSymlinkPolicySkip(t *testing.T) {
	partial := &archivepkg.PartialError{Kind: "symlink", Entry: "link", Err: errors.New("symlink entries are not scanned")}
	coverage := &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureArchive: 1},
		Failures: []engine.ScanFailure{{Kind: engine.FailureArchive, Source: "link", Err: partial}},
	}
	if !corruptArchiveCoverageOnly(coverage) {
		t.Fatal("immutable archive symlink policy skip must be accepted")
	}
}

func TestCorruptArchiveCoverageOnlyRejectsTruncatedFailures(t *testing.T) {
	partial := &archivepkg.PartialError{Kind: "corrupt-entry", Entry: "broken.tar", Err: io.ErrUnexpectedEOF}
	coverage := &engine.DegradedError{
		Total: 2, Counts: map[engine.FailureKind]int{engine.FailureArchive: 2},
		Failures: []engine.ScanFailure{{Kind: engine.FailureArchive, Source: "broken.tar", Err: partial}},
	}
	if corruptArchiveCoverageOnly(coverage) {
		t.Fatal("truncated failure details must remain fatal")
	}
}

func TestCorruptArchiveCoverageOnlyRejectsJoinedFatalError(t *testing.T) {
	partial := &archivepkg.PartialError{Kind: "corrupt-entry", Entry: "broken.tar", Err: io.ErrUnexpectedEOF}
	coverage := &engine.DegradedError{
		Total: 1, Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{
			Kind: engine.FailureSource,
			Err:  errors.Join(partial, errors.New("provider failure")),
		}},
	}
	if corruptArchiveCoverageOnly(coverage) {
		t.Fatal("joined fatal error must remain fatal")
	}
}

func TestCorruptArchiveCoverageOnlyAcceptsCorruptEntryWithSymlinkSiblings(t *testing.T) {
	var archiveData bytes.Buffer
	writer := zip.NewWriter(&archiveData)
	brokenHeader := &zip.FileHeader{Name: "broken.txt", Method: zip.Store}
	broken, err := writer.CreateHeader(brokenHeader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Write([]byte("ordinary fixture data")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		header := &zip.FileHeader{Name: fmt.Sprintf("link-%d", i), Method: zip.Store}
		header.SetMode(os.ModeSymlink | 0o777)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("target")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	corrupt := append([]byte(nil), archiveData.Bytes()...)
	if len(corrupt) < 30 || !bytes.Equal(corrupt[:4], []byte{'P', 'K', 3, 4}) {
		t.Fatal("fixture has no local ZIP header")
	}
	nameLen := int(corrupt[26]) | int(corrupt[27])<<8
	extraLen := int(corrupt[28]) | int(corrupt[29])<<8
	dataOffset := 30 + nameLen + extraLen
	if dataOffset >= len(corrupt) {
		t.Fatal("fixture has no entry body")
	}
	corrupt[dataOffset] ^= 0xff

	archiveErr := archivepkg.WalkStreamContext(
		context.Background(),
		"fixture.zip",
		bytes.NewReader(corrupt),
		int64(len(corrupt)),
		archivepkg.Limits{},
		func(archivepkg.StreamEntry) error { return nil },
	)
	if archiveErr == nil {
		t.Fatal("fixture must produce archive degradation")
	}
	gitCoverage := &engine.DegradedError{
		Total:  1,
		Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{
			Kind: engine.FailureSource,
			Err:  fmt.Errorf("git: expand archive: %w", archiveErr),
		}},
	}
	githubCoverage := &engine.DegradedError{
		Total:  1,
		Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{
			Kind: engine.FailureSource,
			Err:  gitCoverage,
		}},
	}
	coverage, residual := engine.PartitionDegradedErrors(errors.Join(githubCoverage))
	if residual != nil {
		t.Fatalf("residual error = %v", residual)
	}
	if !corruptArchiveCoverageOnly(coverage) {
		t.Fatal("immutable corrupt entry with safely skipped symlinks must be accepted")
	}
}

func TestRunScanCommonFatalRunRestoresPriorFlushedCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	baseline := &retryAfterDegradedSource{fingerprint: "before"}
	if err := runScanCommon(scanGitHubCmd, baseline, nil, "github-fatal-restore"); err != nil {
		t.Fatalf("baseline run: %v", err)
	}
	fatalSource := &retryAfterDegradedSource{fatal: true, fingerprint: "after"}
	if err := runScanCommon(scanGitHubCmd, fatalSource, nil, "github-fatal-restore"); err == nil {
		t.Fatal("fatal source run unexpectedly succeeded")
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "before" || string(entry.SourceState) != `"complete"` {
			t.Fatalf("fatal run left partial checkpoint = %+v, want prior complete entry", entry)
		}
	}
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRunScanCommonOutputCloseFailureRestoresPriorCheckpoint(t *testing.T) {
	resetCommandFlags(t)
	scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
	scanOpts.format, scanOpts.failOn = "json", "critical"
	scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
	scanGitHubCmd.SetContext(context.Background())
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)

	baseline := &retryAfterDegradedSource{fingerprint: "before"}
	if err := runScanCommon(scanGitHubCmd, baseline, nil, "github-close-restore"); err != nil {
		t.Fatalf("baseline run: %v", err)
	}
	writeErr := errors.New("injected final output failure")
	Root.SetOut(failingWriter{err: writeErr})
	next := &retryAfterDegradedSource{fingerprint: "after"}
	err := runScanCommon(scanGitHubCmd, next, nil, "github-close-restore")
	if !errors.Is(err, writeErr) {
		t.Fatalf("run error = %v, want final output failure", err)
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range state.Entries {
		if entry.ResourceFingerprint != "before" || string(entry.SourceState) != `"complete"` {
			t.Fatalf("output failure advanced checkpoint = %+v, want prior complete entry", entry)
		}
	}
}

func TestGitHubCollaborationIncrementalCLIJSONAndSARIFE2E(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			resetCommandFlags(t)
			scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
			scanOpts.format, scanOpts.failOn = format, "critical"
			scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
			scanGitHubCmd.SetContext(context.Background())
			run := func(src *incrementalCollaborationSource) (string, error) {
				var out, stderr bytes.Buffer
				Root.SetOut(&out)
				Root.SetErr(&stderr)
				err := runScanCommon(scanGitHubCmd, src, nil, "github-collaboration-e2e-"+format)
				return out.String(), err
			}
			first, err := run(&incrementalCollaborationSource{})
			if err != nil && !errors.Is(err, errFindingsFound) {
				t.Fatalf("first run: %v", err)
			}
			for _, want := range []string{"issue", "pull_request", "body", "acme/repo"} {
				if !strings.Contains(first, want) {
					t.Fatalf("%s output missing %q: %s", format, want, first)
				}
			}
			second, err := run(&incrementalCollaborationSource{})
			if err != nil {
				t.Fatalf("incremental rerun: %v", err)
			}
			if format == "json" {
				if strings.TrimSpace(second) != "[]" {
					t.Fatalf("incremental JSON re-emitted body: %s", second)
				}
			} else if strings.Contains(second, "source_entity") || strings.Contains(second, "github_pat") {
				t.Fatalf("incremental SARIF re-emitted body: %s", second)
			}
		})
	}
}

func TestGitHubWikiIncrementalCLIJSONAndSARIFE2E(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			resetCommandFlags(t)
			scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
			scanOpts.format, scanOpts.failOn = format, "critical"
			scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
			scanGitHubCmd.SetContext(context.Background())
			run := func(src *incrementalWikiSource) string {
				var out, stderr bytes.Buffer
				Root.SetOut(&out)
				Root.SetErr(&stderr)
				if err := runScanCommon(scanGitHubCmd, src, nil, "github-wiki-e2e-"+format); err != nil && !errors.Is(err, errFindingsFound) {
					t.Fatal(err)
				}
				return out.String()
			}
			first := run(&incrementalWikiSource{})
			for _, want := range []string{"wiki", "page", "Runbook", "acme/repo"} {
				if !strings.Contains(first, want) {
					t.Fatalf("%s missing %q: %s", format, want, first)
				}
			}
			second := run(&incrementalWikiSource{})
			if format == "json" && strings.TrimSpace(second) != "[]" {
				t.Fatalf("wiki re-emitted: %s", second)
			}
			if format == "sarif" && strings.Contains(second, "source_entity") {
				t.Fatalf("wiki re-emitted: %s", second)
			}
		})
	}
}

func TestGitHubGistIncrementalCLIJSONAndSARIFE2E(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			resetCommandFlags(t)
			scanOpts.noVerify, scanOpts.quiet, scanOpts.incremental = true, true, true
			scanOpts.format, scanOpts.failOn = format, "critical"
			scanOpts.incrementalState = filepath.Join(t.TempDir(), "state.json")
			scanGitHubCmd.SetContext(context.Background())
			run := func(src *incrementalGistSource) string {
				var out, stderr bytes.Buffer
				Root.SetOut(&out)
				Root.SetErr(&stderr)
				if err := runScanCommon(scanGitHubCmd, src, nil, "github-gist-e2e-"+format); err != nil && !errors.Is(err, errFindingsFound) {
					t.Fatal(err)
				}
				return out.String()
			}
			first := run(&incrementalGistSource{})
			for _, want := range []string{"gist", "content", "abc123"} {
				if !strings.Contains(first, want) {
					t.Fatalf("%s missing %q: %s", format, want, first)
				}
			}
			if format == "json" {
				for _, want := range []string{`"link": "https://gist.github.com/abc123"`, `"visibility": "secret"`, `"entity": "gist"`, `"part": "content"`} {
					if !strings.Contains(first, want) {
						t.Fatalf("JSON provenance missing %s: %s", want, first)
					}
				}
			} else {
				for _, want := range []string{`"source_link": "https://gist.github.com/abc123"`, `"source_visibility": "secret"`, `"source_entity": "gist"`, `"source_part": "content"`} {
					if !strings.Contains(first, want) {
						t.Fatalf("SARIF provenance missing %s: %s", want, first)
					}
				}
			}
			second := run(&incrementalGistSource{})
			if format == "json" && strings.TrimSpace(second) != "[]" {
				t.Fatalf("gist re-emitted: %s", second)
			}
			if format == "sarif" && strings.Contains(second, "source_entity") {
				t.Fatalf("gist re-emitted: %s", second)
			}
		})
	}
}

func TestScanGitHelp(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "git", "--help"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan git --help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--repo", "--branch", "all safe advertised history refs", "--since", "--max-depth", "--include", "--exclude", "--include-commit-metadata", "--skip-merge-commits", "--trufflehog-compatible", "--include-git-archives", "--include-git-binaries", "hard cap 2 GiB", "--git-archive-timeout"} {
		if !strings.Contains(got, want) {
			t.Errorf("scan git help missing %q in:\n%s", want, got)
		}
	}
}

func TestIsFindingsError(t *testing.T) {
	if !IsFindingsError(errFindingsFound) {
		t.Errorf("sentinel must match itself")
	}
	if IsFindingsError(nil) {
		t.Errorf("nil must not match")
	}
}

func TestParseFailOn(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"any", false},
		{"", false},
		{"info", false},
		{"low", false},
		{"medium", false},
		{"high", false},
		{"critical", false},
		{"CRITICAL", false},
		{" critical ", false},
		{"extreme", true},
		{"verified", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := parseFailOn(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseFailOn(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestScanFailOnGate(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--rules", rules, "--fail-on", "critical", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if IsFindingsError(err) {
		t.Fatalf("--fail-on=critical should not trip on High; output:\n%s", out.String())
	}
}

// TestFailOnDefaultIsHigh pins the audit-first default (#250): a
// first-time adopter who never passes --fail-on must get "high", not
// the old "any". Checked against both commands that expose the flag —
// scan (persistent) and protect (its own local copy of the same flag,
// see protect.go) — since a mismatch between the two would silently
// reintroduce enforce-first behaviour for one of them.
func TestFailOnDefaultIsHigh(t *testing.T) {
	f := scanCmd.PersistentFlags().Lookup("fail-on")
	if f == nil {
		t.Fatal("scan: --fail-on flag not registered")
	}
	if f.DefValue != "high" {
		t.Errorf("scan --fail-on default = %q, want %q (audit-first rollout, #250)", f.DefValue, "high")
	}

	pf := protectCmd.Flags().Lookup("fail-on")
	if pf == nil {
		t.Fatal("protect: --fail-on flag not registered")
	}
	if pf.DefValue != "high" {
		t.Errorf("protect --fail-on default = %q, want %q (audit-first rollout, #250)", pf.DefValue, "high")
	}
}

// TestScanFailOnDefault_LowSeverityFindingExitsZero is the acceptance
// scenario from #250: a fresh `scan filesystem` run against a target
// with one low-severity finding must exit 0 by default (no --fail-on
// passed) and must explain, on stderr, why nothing failed the build
// and how to tighten the gate. Before #250 the default was "any" and
// this same finding would have exited 1.
func TestScanFailOnDefault_LowSeverityFindingExitsZero(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/notes.txt"
	if err := writeFile(target, "acme_ref: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Reference",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"low"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	// Deliberately no --fail-on: exercise the default.
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err != nil {
		t.Fatalf("default --fail-on=high must not trip on a Low finding; err=%v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	// Raw secret bytes are redacted in JSON output by design; assert on
	// the custom-rule name that rides through in extra_data instead.
	if !strings.Contains(out.String(), "ACME Reference") {
		t.Errorf("finding must still be emitted (audit, don't hide); output:\n%s", out.String())
	}
	stderr := errBuf.String()
	if !strings.Contains(stderr, "exit gate: --fail-on=high") {
		t.Errorf("expected exit-gate hint naming the active gate; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "1 low") {
		t.Errorf("expected hint to count the below-gate finding; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--fail-on=any") {
		t.Errorf("expected hint to name the escape hatch to block on all; stderr:\n%s", stderr)
	}
}

func TestBlastRadiusFilterSink_DropsAndForwards(t *testing.T) {
	captured := &captureSink{}
	bf := &blastRadiusFilterSink{inner: captured}

	br := engineFinding(detectors.AWS, true, "AKIA…")
	if br.Result.ExtraData == nil {
		br.Result.ExtraData = map[string]string{}
	}
	br.Result.ExtraData["blast_radius"] = "true"
	bf.Emit(br)

	bf.Emit(engineFinding(detectors.AWS, true, "AKIA…2"))

	if got := len(captured.findings); got != 1 {
		t.Errorf("expected 1 finding forwarded, got %d", got)
	}
	if dr := bf.dropped.Load(); dr != 1 {
		t.Errorf("expected dropped=1, got %d", dr)
	}
}

func TestVerifiedOnlySink_DropsUnverified(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured}

	vo.Emit(engineFinding(detectors.GitHub, false, "ghp_unverified"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 1 {
		t.Fatalf("expected only verified finding forwarded, got %d", got)
	}
	if !captured.findings[0].Result.Verified {
		t.Fatal("forwarded finding must be verified")
	}
	if dropped := vo.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

func TestProviderConfirmedOnlySinkBlocksWeakAssuranceBeforeSideEffects(t *testing.T) {
	sideEffects := &captureSink{}
	strict := &providerConfirmedOnlySink{inner: sideEffects}

	legacy := engineFinding(detectors.GitHub, true, "legacy")
	responseConfirmed := engineFinding(detectors.GitHub, true, "response")
	responseConfirmed.Result.VerificationAssurance = detectors.AssuranceResponseConfirmed
	providerConfirmed := engineFinding(detectors.GitHub, true, "provider")
	providerConfirmed.Result.VerificationAssurance = detectors.AssuranceProviderConfirmed
	indeterminate := engineFindingIndeterminate(detectors.GitHub, "indeterminate")
	indeterminate.Result.VerificationAssurance = detectors.AssuranceProviderConfirmed

	strict.Emit(legacy)
	strict.Emit(responseConfirmed)
	strict.Emit(providerConfirmed)
	strict.Emit(indeterminate)

	if got := len(sideEffects.findings); got != 1 {
		t.Fatalf("expected only provider-confirmed finding forwarded, got %d", got)
	}
	if got := sideEffects.findings[0].Result.VerificationAssurance; got != detectors.AssuranceProviderConfirmed {
		t.Fatalf("forwarded assurance = %v, want provider-confirmed", got)
	}
	if got := strict.dropped.Load(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}

func TestProviderConfirmedOnlySinkAlsoGuardsSuppressedAuditOutput(t *testing.T) {
	captured := &captureSink{}
	strictAudit := &providerConfirmedOnlySink{inner: captured}
	placeholder := engine.NewPlaceholderFilter(&captureSink{}, strictAudit)

	legacy := engineFinding(detectors.GitHub, true, "changeme")
	placeholder.Emit(legacy)
	if got := len(captured.findings); got != 0 {
		t.Fatalf("legacy suppressed finding bypassed strict audit gate: %d", got)
	}

	providerConfirmed := engineFinding(detectors.GitHub, true, "changeme")
	providerConfirmed.Result.VerificationAssurance = detectors.AssuranceProviderConfirmed
	placeholder.Emit(providerConfirmed)
	if got := len(captured.findings); got != 1 {
		t.Fatalf("provider-confirmed suppressed finding count = %d, want 1", got)
	}
}

func TestScanOnlyProviderConfirmedDropsLegacyVerifiedFinding(t *testing.T) {
	resetCommandFlags(t)

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rules := filepath.Join(t.TempDir(), "rules.json")
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"verify_url":"%s"
	}]`, srv.URL)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetIn(strings.NewReader("ACME_1234567890ABCDEFGHIJ"))
	Root.SetArgs([]string{
		"scan", "--rules", rules, "--only-provider-confirmed", "--format", "json", "stdin",
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("strict scan should drop legacy verified finding without failing: %v\nstderr:\n%s", err, errBuf.String())
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("strict output = %q, want empty JSON array", out.String())
	}
	if requests.Load() != 0 {
		t.Fatalf("verification requests = %d, want 0 for an unaudited detector", requests.Load())
	}
}

func TestScanVerifyMinAssurancePreservesUnauditedCandidateWithoutRequest(t *testing.T) {
	resetCommandFlags(t)

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rules := filepath.Join(t.TempDir(), "rules.json")
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"verify_url":"%s"
	}]`, srv.URL)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetIn(strings.NewReader("ACME_1234567890ABCDEFGHIJ"))
	Root.SetArgs([]string{
		"scan", "--rules", rules,
		"--verify-min-assurance", "provider-confirmed",
		"--fail-on", "critical",
		"--format", "json", "stdin",
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("audit scan failed: %v\nstderr:\n%s", err, errBuf.String())
	}
	var findings []struct {
		Verified              bool   `json:"verified"`
		VerificationAssurance string `json:"verification_assurance"`
	}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("decode output: %v\noutput:\n%s", err, out.String())
	}
	if len(findings) != 1 || findings[0].Verified ||
		findings[0].VerificationAssurance != "unknown" {
		t.Fatalf("findings = %+v, want one unaudited candidate", findings)
	}
	if requests.Load() != 0 {
		t.Fatalf("verification requests = %d, want 0 for an unaudited detector", requests.Load())
	}
}

// engineFindingIndeterminate builds a Finding whose verification attempt
// failed (VerificationErr set, Verified false) — the shape a real detector
// produces on a network error / provider 5xx / rate limit rather than an
// affirmative "not live" response.
func engineFindingIndeterminate(t detectors.DetectorType, raw string) engine.Finding {
	f := engineFinding(t, false, raw)
	f.Result.VerificationErr = errors.New("dial tcp: connection refused")
	return f
}

// TestVerifiedOnlySink_KeepsIndeterminateByDefault pins the core #246 fix:
// --only-verified must not silently drop a finding whose verification
// attempt failed outright, because that's indistinguishable from "provider
// confirmed dead" once collapsed to a bool — exactly the bug this issue is
// about. The default (no --drop-indeterminate) keeps it and counts it
// separately from the confirmed-dead drops.
func TestVerifiedOnlySink_KeepsIndeterminateByDefault(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured}

	vo.Emit(engineFinding(detectors.GitHub, false, "ghp_confirmed_dead"))
	vo.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 2 {
		t.Fatalf("expected verified + indeterminate forwarded, got %d", got)
	}
	var sawIndeterminate, sawVerified bool
	for _, f := range captured.findings {
		switch f.Result.Verdict() {
		case detectors.VerdictIndeterminate:
			sawIndeterminate = true
		case detectors.VerdictVerified:
			sawVerified = true
		case detectors.VerdictUnverified:
			t.Errorf("confirmed-dead finding must not be forwarded: %v", f.Result.Raw)
		}
	}
	if !sawIndeterminate || !sawVerified {
		t.Fatalf("expected both indeterminate and verified forwarded; got %+v", captured.findings)
	}
	if got := vo.indeterminate.Load(); got != 1 {
		t.Errorf("indeterminate counter = %d, want 1", got)
	}
	if got := vo.dropped.Load(); got != 1 {
		t.Errorf("dropped counter = %d, want 1 (only the confirmed-dead finding)", got)
	}
}

// TestVerifiedOnlySink_DropIndeterminateFlag pins the --drop-indeterminate
// opt-out: when set, indeterminate findings are dropped like confirmed-dead
// ones, restoring the pre-#246 strict behaviour for callers that would
// rather under-report than see an unconfirmed finding.
func TestVerifiedOnlySink_DropIndeterminateFlag(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured, dropIndeterminate: true}

	vo.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 1 {
		t.Fatalf("expected only verified finding forwarded, got %d", got)
	}
	if captured.findings[0].Result.Verdict() != detectors.VerdictVerified {
		t.Fatalf("forwarded finding must be verified, got %v", captured.findings[0].Result.Verdict())
	}
	if got := vo.indeterminate.Load(); got != 1 {
		t.Errorf("indeterminate counter = %d, want 1 (still counted even though dropped)", got)
	}
	if got := vo.dropped.Load(); got != 1 {
		t.Errorf("dropped counter = %d, want 1", got)
	}
}

// TestRevokingSink_NeverRevokesIndeterminate pins the acceptance criterion
// from issue #246: revocation must never fire on an Indeterminate verdict.
// A failed verification attempt means liveness is unknown, not confirmed —
// dispatching Revoke on that basis could invalidate a credential that was
// never actually shown to be live.
func TestRevokingSink_NeverRevokesIndeterminate(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	var auditBuf bytes.Buffer
	rs := newRevokingSink(captured, []detectors.Detector{det}, false, &bytes.Buffer{}, audit.NewWriter(&auditBuf))
	rs.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))

	if rev.calls != 0 {
		t.Errorf("expected 0 revoke calls for an indeterminate verdict, got %d", rev.calls)
	}
	if rs.attempted.Load() != 0 {
		t.Errorf("attempted = %d, want 0", rs.attempted.Load())
	}
	// Same as an Unverified finding: revokingSink's "skipped" counter
	// tracks "verified but no Revoker for this detector", a distinct
	// reason from "not eligible for revoke at all". Neither Unverified
	// nor Indeterminate findings reach that branch.
	if rs.skipped.Load() != 0 {
		t.Errorf("skipped = %d, want 0", rs.skipped.Load())
	}
	if got := len(captured.findings); got != 1 {
		t.Errorf("finding must still be forwarded downstream, got %d", got)
	}
	if got := captured.findings[0].Result.ExtraData["audit_trail_id"]; got != "" {
		t.Errorf("indeterminate finding must not be stamped with audit_trail_id, got %q", got)
	}
	if auditBuf.Len() != 0 {
		t.Errorf("no revoke was attempted; audit trail must stay empty, got:\n%s", auditBuf.String())
	}
}

func TestScan_RevokeOnVerified_RefusesWithoutEnv(t *testing.T) {
	resetCommandFlags(t)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "no secrets here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--revoke-on-verified", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err == nil {
		t.Fatalf("scan must refuse --revoke-on-verified without %s=1", EnvAllowRevoke)
	}
	if !strings.Contains(err.Error(), EnvAllowRevoke) {
		t.Errorf("error must mention %s: %v", EnvAllowRevoke, err)
	}
}

func TestScan_RevokeOnVerified_DryRunBypassesEnv(t *testing.T) {
	resetCommandFlags(t)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "nothing here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})

	if err := Root.Execute(); err != nil {
		t.Fatalf("dry-run with no findings should succeed; got %v\nstderr:\n%s", err, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "revoke:") {
		t.Errorf("expected revoke summary on stderr; got:\n%s", errBuf.String())
	}
}

// TestScan_UnknownPIIEngineIsHardError guards F32: a mistyped --pii-engine
// value must fail loudly at the CLI boundary rather than being swallowed by
// startPIIEngine's "continue without PII" downgrade, which would silently
// produce a secret-only scan the operator reads as a full DLP pass.
func TestScan_UnknownPIIEngineIsHardError(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "nothing here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--pii-engine", "opf", "--no-verify", "filesystem", target})

	err := Root.Execute()
	if err == nil {
		t.Fatalf("scan must reject an unknown --pii-engine value")
	}
	if !strings.Contains(err.Error(), "unknown --pii-engine") || !strings.Contains(err.Error(), "opf") {
		t.Errorf("error must name the bad value: %v", err)
	}
}

// TestScan_ValidPIIEngineOffIsAccepted pins the complement of the F32 gate:
// the recognized values (here "off") pass validation and scan normally, so
// the hard error above cannot regress into rejecting legitimate input.
func TestScan_ValidPIIEngineOffIsAccepted(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/clean.txt"
	if err := writeFile(target, "nothing here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--pii-engine", "off", "--no-verify", "filesystem", target})

	if err := Root.Execute(); err != nil {
		t.Fatalf("--pii-engine off must be accepted; got %v\nstderr:\n%s", err, errBuf.String())
	}
}

// TestScan_ConcurrencyBelowOneIsHardError guards F32: --concurrency < 1 was
// silently clamped to 8 inside the engine, so `--concurrency 0` scanned as if
// unset with no signal. Reject it at the CLI boundary instead.
func TestScan_ConcurrencyBelowOneIsHardError(t *testing.T) {
	for _, n := range []string{"0", "-1"} {
		resetCommandFlags(t)

		dir := t.TempDir()
		target := dir + "/clean.txt"
		if err := writeFile(target, "nothing here\n"); err != nil {
			t.Fatalf("seed: %v", err)
		}

		var out, errBuf bytes.Buffer
		Root.SetOut(&out)
		Root.SetErr(&errBuf)
		Root.SetArgs([]string{"scan", "--concurrency", n, "--no-verify", "filesystem", target})

		err := Root.Execute()
		if err == nil {
			t.Fatalf("--concurrency %s must be rejected", n)
		}
		if !strings.Contains(err.Error(), "--concurrency must be >= 1") {
			t.Errorf("--concurrency %s: unexpected error %v", n, err)
		}
	}
}

func TestRevokingSink_VerifiedFindingDispatches(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	var auditBuf bytes.Buffer
	rs := newRevokingSink(captured, []detectors.Detector{det}, false, &bytes.Buffer{}, audit.NewWriter(&auditBuf))
	rs.Emit(engineFinding(detectors.GitHub, true, "ghp_verified_secret"))
	rs.Emit(engineFinding(detectors.GitHub, false, "ghp_yyy"))

	if got := len(captured.findings); got != 2 {
		t.Errorf("expected both findings forwarded, got %d", got)
	}
	if rev.calls != 1 {
		t.Errorf("expected 1 revoke call (verified only), got %d", rev.calls)
	}
	if rs.attempted.Load() != 1 || rs.revoked.Load() != 1 {
		t.Errorf("counters: attempted=%d revoked=%d, want 1/1", rs.attempted.Load(), rs.revoked.Load())
	}

	// The verified finding forwarded downstream (and thus into any
	// json/sarif output) must carry the same trail id as the audit
	// trail record — that link is how a SARIF/json consumer correlates
	// a finding to its revoke outcome (issue #304).
	trailID := captured.findings[0].Result.ExtraData["audit_trail_id"]
	if trailID == "" {
		t.Fatal("verified+revoked finding must be stamped with a non-empty audit_trail_id")
	}
	if got := captured.findings[1].Result.ExtraData["audit_trail_id"]; got != "" {
		t.Errorf("unverified finding must not be stamped with audit_trail_id, got %q", got)
	}

	rec := decodeSoleAuditRecord(t, auditBuf.Bytes())
	if rec.SchemaVersion != audit.SchemaVersion {
		t.Errorf("audit record schema_version = %q, want %q", rec.SchemaVersion, audit.SchemaVersion)
	}
	if rec.TrailID != trailID {
		t.Errorf("audit record trail_id = %q, want %q (must match the stamped finding)", rec.TrailID, trailID)
	}
	if rec.Path != string(audit.PathOnVerified) {
		t.Errorf("audit record path = %q, want %q", rec.Path, audit.PathOnVerified)
	}
	if rec.Detector != detectors.GitHub.String() {
		t.Errorf("audit record detector = %q, want %q", rec.Detector, detectors.GitHub.String())
	}
	if !rec.Revoked {
		t.Error("audit record revoked = false, want true (fakeRevoker always succeeds)")
	}
	if rec.SecretHash != audit.HashSecret("ghp_verified_secret") {
		t.Errorf("audit record secret_hash = %q, want hash of the raw secret", rec.SecretHash)
	}
	if strings.Contains(auditBuf.String(), "ghp_verified_secret") {
		t.Fatalf("audit trail leaked the raw secret: %s", auditBuf.String())
	}
}

func TestRevokingSink_DryRunDoesNotCallProvider(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	var logBuf, auditBuf bytes.Buffer
	rs := newRevokingSink(captured, []detectors.Detector{det}, true, &logBuf, audit.NewWriter(&auditBuf))
	rs.Emit(engineFinding(detectors.GitHub, true, "ghp_xxx"))

	if rev.calls != 0 {
		t.Errorf("dry-run must not call provider; got %d calls", rev.calls)
	}
	if !strings.Contains(logBuf.String(), "DRY-RUN") {
		t.Errorf("dry-run must log preview line; got:\n%s", logBuf.String())
	}

	rec := decodeSoleAuditRecord(t, auditBuf.Bytes())
	if !rec.DryRun {
		t.Error("dry-run audit record must set dry_run=true")
	}
	if rec.Revoked {
		t.Error("dry-run audit record must not claim revoked=true")
	}
	if rec.SchemaVersion != audit.SchemaVersion {
		t.Errorf("audit record schema_version = %q, want %q", rec.SchemaVersion, audit.SchemaVersion)
	}
}

// decodeSoleAuditRecord decodes exactly one JSON Lines audit.Record from
// b, failing the test if there isn't exactly one well-formed line.
func decodeSoleAuditRecord(t *testing.T, b []byte) audit.Record {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one audit trail line, got %d: %q", len(lines), string(b))
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode audit record: %v\nline: %s", err, lines[0])
	}
	return rec
}

func TestScanFilesystemWithCustomRules(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "filesystem", target})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error; got %v\noutput: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "ACME_QWERTYUIOPASDFGHJKLZ") &&
		!strings.Contains(out.String(), "ACME Token") &&
		!strings.Contains(out.String(), "ACME") {
		t.Errorf("output missing custom rule hit:\n%s", out.String())
	}
}

// unreachableLocalPort binds an ephemeral loopback port and immediately
// closes it, so nothing listens there. Dialing it fails fast with
// "connection refused" — deterministic and independent of any external
// network reachability, unlike a real DNS-resolved unreachable host.
func unreachableLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// TestScan_OnlyVerifiedKeepsIndeterminateFinding is the issue #246 scenario
// test: a custom rule's verify_url points at an unreachable local port, so
// every verification attempt fails with a transport error rather than an
// affirmative "not live" response. With --only-verified, the finding must
// still be emitted (marked indeterminate, not silently dropped) and a
// stderr warning must report the count — collapsing Verified=false here
// would make a live credential caught in a provider outage indistinguishable
// from "no secrets found".
func TestScan_OnlyVerifiedKeepsIndeterminateFinding(t *testing.T) {
	resetCommandFlags(t)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--only-verified", "--format", "json", "filesystem", target})

	execErr := Root.Execute()
	if !IsFindingsError(execErr) {
		t.Fatalf("expected findings error (indeterminate finding kept); got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("want 1 finding kept, got %d\nstdout:\n%s", len(records), out.String())
	}
	if records[0]["verdict"] != "indeterminate" {
		t.Errorf("verdict = %v, want indeterminate", records[0]["verdict"])
	}
	if records[0]["verified"] != false {
		t.Errorf("verified = %v, want false", records[0]["verified"])
	}
	if records[0]["verification_error"] == nil || records[0]["verification_error"] == "" {
		t.Errorf("verification_error must be populated, got %v", records[0]["verification_error"])
	}

	if !strings.Contains(errBuf.String(), "only-verified: kept 1 indeterminate finding") {
		t.Errorf("expected stderr warning about the kept indeterminate finding; stderr:\n%s", errBuf.String())
	}
}

// TestScan_OnlyVerifiedDropIndeterminateFlag exercises the --drop-indeterminate
// opt-out against the same unreachable-verifier scenario: the finding must
// be excluded entirely, and the scan must report success (no findings kept).
func TestScan_OnlyVerifiedDropIndeterminateFlag(t *testing.T) {
	resetCommandFlags(t)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--only-verified", "--drop-indeterminate", "--format", "json", "filesystem", target})

	execErr := Root.Execute()
	if IsFindingsError(execErr) {
		t.Fatalf("expected no findings error (indeterminate finding dropped); got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	} else if execErr != nil {
		t.Fatalf("unexpected error: %v", execErr)
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 0 {
		t.Fatalf("want 0 findings kept, got %d\nstdout:\n%s", len(records), out.String())
	}
	if !strings.Contains(errBuf.String(), "only-verified: dropped 1 indeterminate finding") {
		t.Errorf("expected stderr warning about the dropped indeterminate finding; stderr:\n%s", errBuf.String())
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// TestScanGit_DefaultReportsUnverifiedFinding is the issue #273 regression
// test: `scan git` (default flags — no --only-verified, no
// --all-occurrences) must report the same finding that `scan filesystem`
// and `scan stdin` report for identical content. Before the fix,
// engine.NewGitCrossCommitDedup buffered every finding until Close, but
// runScanCommon only ever closed the raw output sink, not the sink chain
// feeding it — so every git-mode finding was silently dropped regardless
// of its verdict.
//
// The custom rule's verify_url points at an unreachable local port so the
// verification outcome (indeterminate) is deterministic and offline,
// mirroring TestScan_OnlyVerifiedKeepsIndeterminateFinding.
func TestScanGit_DefaultReportsUnverifiedFinding(t *testing.T) {
	resetCommandFlags(t)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	target := filepath.Join(dir, "leak.txt")
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	if _, err := wt.Add("leak.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	sig := &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := wt.Commit("add-leak", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rules := filepath.Join(dir, "rules.json")
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "git", "--repo", dir})

	execErr := Root.Execute()
	if !IsFindingsError(execErr) {
		t.Fatalf("expected findings error; got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("want 1 finding, got %d\nstdout:\n%s", len(records), out.String())
	}
	if records[0]["verdict"] != "indeterminate" {
		t.Errorf("verdict = %v, want indeterminate", records[0]["verdict"])
	}
	if !strings.Contains(errBuf.String(), "scanned 1 chunk(s)") || strings.Contains(errBuf.String(), "0 finding(s)") {
		t.Errorf("expected non-zero finding count in summary; stderr:\n%s", errBuf.String())
	}
}

func TestScanGit_CommitMessageAndNoteFindingsReachJSON(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	repo, _ := gogit.PlainInit(dir, false)
	wt, _ := repo.Worktree()
	if err := writeFile(filepath.Join(dir, "safe.txt"), "safe\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = wt.Add("safe.txt")
	sig := &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	_, err := wt.Commit("META_TOKEN_MESSAGE_1234567890", &gogit.CommitOptions{Author: sig, Committer: sig})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, "safe.txt"), "safe changed\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = wt.Add("safe.txt")
	sig2 := *sig
	sig2.When = sig.When.Add(time.Minute)
	hash, err := wt.Commit("notes commit", &gogit.CommitOptions{Author: &sig2, Committer: &sig2})
	if err != nil {
		t.Fatal(err)
	}
	// Same value in a different commit's note must survive cross-commit
	// dedup because commit metadata has commit-specific provenance.
	if out, err := exec.Command("git", "-C", dir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "notes", "add", "-m", "META_TOKEN_MESSAGE_1234567890", hash.String()).CombinedOutput(); err != nil {
		t.Fatalf("git notes: %v: %s", err, out)
	}
	rules := filepath.Join(dir, "rules.json")
	if err := writeFile(rules, `[{"name":"Metadata Token","keywords":["META_TOKEN_"],"regex":"META_TOKEN_[A-Z_0-9]{18,}","severity":"high"}]`); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "git", "--repo", dir, "--include-commit-metadata"})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("scan error=%v stderr=%s", err, errBuf.String())
	}
	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("json: %v: %s", err, out.String())
	}
	if len(records) < 2 {
		t.Fatalf("message/note findings missing: %s", out.String())
	}
}

func TestScanStdin_FindsSecretFromPipe(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader("aws_access_key=AKIA1234567890ABCDEF\n"))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin", "--label", "test-pipe"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error from stdin scan; got %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "test-pipe") {
		t.Errorf("expected --label to ride through to output:\n%s", out.String())
	}
}

// TestScanStdin_NoVerifySkipsNetworkCall is the issue #303 CLI-level
// contract test for the fast hook path: --no-verify must genuinely bypass
// the detector's Verify() network round-trip, not merely post-filter a
// verified finding out of the output. A custom rule's verify_url points at
// a real local httptest server that would return 200 (i.e. "verified") if
// ever hit; the assertion is that the server sees zero requests and the
// emitted finding's verdict is unverified rather than verified.
func TestScanStdin_NoVerifySkipsNetworkCall(t *testing.T) {
	resetCommandFlags(t)

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	rules := dir + "/rules.json"
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"%s"
	}]`, srv.URL)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetIn(strings.NewReader("acme_token=ACME_QWERTYUIOPASDFGHJKLZ\n"))
	Root.SetArgs([]string{"scan", "--rules", rules, "--no-verify", "--format", "json", "stdin"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error; got %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}

	if n := requests.Load(); n != 0 {
		t.Errorf("verify server must never be contacted under --no-verify, got %d request(s)", n)
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("want 1 finding, got %d\nstdout:\n%s", len(records), out.String())
	}
	if records[0]["verified"] != false {
		t.Errorf("verified = %v, want false (network verify was skipped)", records[0]["verified"])
	}
}

// TestScan_NoVerifyAndOnlyVerifiedRejected pins the mutual-exclusivity
// guard: combining --no-verify with --only-verified would silently emit
// zero findings every time (nothing is ever verified when verification
// never runs), which reads as a false "clean scan" rather than a
// configuration mistake. The CLI must reject the combination up front.
func TestScan_NoVerifyAndOnlyVerifiedRejected(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader("nothing interesting here\n"))
	Root.SetArgs([]string{"scan", "--no-verify", "--only-verified", "stdin"})

	err := Root.Execute()
	if err == nil {
		t.Fatal("expected --no-verify + --only-verified to be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should name the conflict; got %v", err)
	}
}

func TestScanFilesystemWithAllowlist(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYqWERTY1KEY\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	allow := dir + "/.pleno-allow.json"
	if err := writeFile(allow, `{"entries":[{"path":"leak.txt","reason":"trufflehog dummies"}]}`); err != nil {
		t.Fatalf("seed allow: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--allowlist", allow, "--format", "json", "filesystem", target})

	err := Root.Execute()
	if IsFindingsError(err) {
		t.Fatalf("allowlist should suppress AWS finding; output:\n%s\nstderr:\n%s", out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "allowlist: suppressed") {
		t.Errorf("expected suppression notice on stderr; got:\n%s", errBuf.String())
	}
}

func TestScanFilesystemIncrementalSkipsUnchangedCleanScan(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/clean.txt"
	state := dir + "/state/incremental.json"
	if err := writeFile(target, "ordinary docs with no credential material\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}
	if !strings.Contains(firstErr.String(), "scanned 1 chunk") {
		t.Fatalf("first run should perform the baseline scan; stderr:\n%s", firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("unchanged clean incremental run should skip and succeed: %v\nstderr:\n%s", err, secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("second run should skip; stderr:\n%s", secondErr.String())
	}
}

func TestScanFilesystemIncrementalSkipPreservesFindingExit(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	state := dir + "/incremental.json"
	rules := dir + "/rules.json"
	if err := writeFile(target, "acme_token=ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--rules", rules, "--format", "json", "filesystem", target})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("first baseline should find the custom secret; got %v\nstdout:\n%s\nstderr:\n%s", err, firstOut.String(), firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--rules", rules, "--format", "json", "filesystem", target})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("unchanged finding baseline must preserve finding exit; got %v\nstdout:\n%s\nstderr:\n%s", err, secondOut.String(), secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("second run should skip; stderr:\n%s", secondErr.String())
	}
	if secondOut.Len() != 0 {
		t.Fatalf("skipped scan should not replay stale findings on stdout; got:\n%s", secondOut.String())
	}
}

func TestScanFilesystemIncrementalSkipsRevokeDryRunWhenUnchanged(t *testing.T) {
	resetCommandFlags(t)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/clean.txt"
	state := dir + "/incremental.json"
	if err := writeFile(target, "ordinary docs with no credential material\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("unchanged incremental revoke dry-run should skip cleanly: %v\nstderr:\n%s", err, secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("state match should skip even with revoke-on-verified; stderr:\n%s", secondErr.String())
	}
	if strings.Contains(secondErr.String(), "scanned 1 chunk") {
		t.Fatalf("skipped scan should not run detectors; stderr:\n%s", secondErr.String())
	}
	if strings.Contains(secondErr.String(), "revoke:") {
		t.Fatalf("skipped scan should not emit revoke summary; stderr:\n%s", secondErr.String())
	}
}

func TestScanStdin_TruncatedButFoundStillReportsFindings(t *testing.T) {
	resetCommandFlags(t)

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	secretLine := "aws_access_key=AKIA1234567890ABCDEF\n"
	Root.SetIn(strings.NewReader(secretLine + strings.Repeat("x", 4096)))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin", "--max-bytes", "40"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("truncated stdin with a finding must return errFindingsFound, not the truncation error; got %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "max_bytes") {
		t.Errorf("expected truncation warning on stderr; got:\n%s", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "finding(s)") {
		t.Errorf("expected end-of-scan summary on stderr; got:\n%s", errBuf.String())
	}
}

func TestScanStdin_NoFindingsExitsZero(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader("nothing secret here, just plain text\n"))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin"})

	if err := Root.Execute(); err != nil {
		t.Fatalf("clean stdin scan should succeed; got %v\noutput:\n%s", err, out.String())
	}
}

func TestFilterDetectors_Include(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, []string{"aws", "github"}, nil)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 detectors, got %d", len(got))
	}
}

func TestFilterDetectors_Exclude(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, nil, []string{"AWS"})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 after excluding AWS, got %d", len(got))
	}
	for _, d := range got {
		if d.Type() == detectors.AWS {
			t.Errorf("AWS slipped past exclude")
		}
	}
}

func TestFilterDetectors_IncludeThenExclude(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, []string{"aws", "github"}, []string{"github"})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 1 || got[0].Type() != detectors.AWS {
		t.Fatalf("want only AWS after include={aws,github} exclude={github}, got %+v", got)
	}
}

func TestFilterDetectors_UnknownNameErrors(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}}
	if _, err := filterDetectors(in, []string{"awz"}, nil); err == nil {
		t.Errorf("typo should error, not silently match nothing")
	}
	if _, err := filterDetectors(in, nil, []string{"awz"}); err == nil {
		t.Errorf("typo in exclude should error")
	}
}

func TestFilterDetectors_NoFlagsPassthrough(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}}
	got, err := filterDetectors(in, nil, nil)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != len(in) {
		t.Errorf("no-op filter mutated slice: %d -> %d", len(in), len(got))
	}
}

func TestScanFilesystemFiltersDetectors(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := os.WriteFile(target, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--exclude-detectors", "aws,generichighentropy", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if IsFindingsError(err) {
		t.Fatalf("--exclude-detectors aws should silence the AWS finding; output:\n%s", out.String())
	}
}

// stubDet is a minimal Detector for unit tests that don't care about
// scanning behaviour — only Type() is exercised by filterDetectors.
type stubDet struct{ t detectors.DetectorType }

func (s stubDet) Type() detectors.DetectorType { return s.t }
func (s stubDet) Keywords() []string           { return nil }
func (s stubDet) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}

// captureSink records every Finding it receives so revokingSink tests
// can assert downstream propagation.
type captureSink struct{ findings []engine.Finding }

func (c *captureSink) Emit(f engine.Finding) { c.findings = append(c.findings, f) }
func (c *captureSink) Close() error          { return nil }

// fakeRevoker counts Revoke calls and reports success.
type fakeRevoker struct{ calls int }

func (f *fakeRevoker) Revoke(_ context.Context, _ string) (detectors.RevokeResult, error) {
	f.calls++
	return detectors.RevokeResult{Revoked: true}, nil
}

// fakeDetectorWithRevoker pairs a stub Detector with a Revoker so the
// type assertion inside newRevokingSink picks it up.
type fakeDetectorWithRevoker struct{ Revoker detectors.Revoker }

func (f fakeDetectorWithRevoker) Type() detectors.DetectorType { return detectors.GitHub }
func (f fakeDetectorWithRevoker) Keywords() []string           { return []string{"ghp_"} }
func (f fakeDetectorWithRevoker) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}
func (f fakeDetectorWithRevoker) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	return f.Revoker.Revoke(ctx, secret)
}

// engineFinding builds an engine.Finding so the revoking-sink tests
// read declaratively without reciting the full struct shape.
func engineFinding(t detectors.DetectorType, verified bool, raw string) engine.Finding {
	return engine.Finding{
		Detector: t,
		Result: detectors.Result{
			DetectorType: t,
			Verified:     verified,
			Raw:          []byte(raw),
		},
	}
}
