package crash

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the entry point for the crash subprocess started by
// TestInstallCapturesGoroutinePanic: when CRASH_TEST_HELPER=1 it runs
// helperCrash instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("CRASH_TEST_HELPER") == "1" {
		helperCrash()
		return
	}
	os.Exit(m.Run())
}

// helperCrash installs real crash capture and then panics on a non-main
// goroutine, proving the runtime's own writer catches the case the old
// main-goroutine-only crash.Recover could not.
func helperCrash() {
	if _, err := Install(Config{Dir: os.Getenv("CRASH_TEST_DIR")}); err != nil {
		os.Stderr.WriteString("install: " + err.Error() + "\n")
		os.Exit(3)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		panic("crash-helper-boom")
	}()
	<-done
}

// stubCrashOutput replaces the runtime seam so tests can exercise Install
// without the process-global "at most once" restriction of
// debug.SetCrashOutput.
func stubCrashOutput(t *testing.T) {
	t.Helper()
	old := setCrashOutput
	setCrashOutput = func(*os.File, debug.CrashOptions) error { return nil }
	t.Cleanup(func() { setCrashOutput = old })
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInstallCapturesGoroutinePanic(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		"CRASH_TEST_HELPER=1",
		"CRASH_TEST_DIR="+dir,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Fatalf("helper exited 0; want crash. output:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("helper failed to run: %v", runErr)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("helper exit code = %d, want 2. output:\n%s", exitErr.ExitCode(), out)
	}

	dumps, err := Pending(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dumps) != 1 {
		t.Fatalf("Pending returned %d dumps, want 1. output:\n%s", len(dumps), out)
	}
	if !bytes.Contains(dumps[0].Data, []byte("crash-helper-boom")) {
		t.Fatalf("dump missing panic message:\n%s", dumps[0].Data)
	}
	if !bytes.Contains(dumps[0].Data, []byte("goroutine")) {
		t.Fatalf("dump does not look like a runtime dump:\n%s", dumps[0].Data)
	}
}

func TestSessionCloseRemovesEmptySpool(t *testing.T) {
	stubCrashOutput(t)
	dir := t.TempDir()
	s, err := Install(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := s.Path()
	if path == "" {
		t.Fatal("Install returned an empty spool path")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("spool file not created: %v", err)
	}
	if got := s.Dir(); got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}
	s.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty spool survived Close: %v", err)
	}
	s.Close() // idempotent
}

func TestInstallDisabledCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := Install(Config{Dir: dir, Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Path() != "" {
		t.Fatalf("Path() = %q, want empty", s.Path())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("spool dir created despite Disabled: %v", err)
	}
}

func TestEnvDisableSkipsInstall(t *testing.T) {
	t.Setenv(EnvDisable, "1")
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := Install(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Path() != "" {
		t.Fatalf("Path() = %q, want empty", s.Path())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("spool dir created despite %s: %v", EnvDisable, err)
	}
}

func TestInstallPrunesOldDumps(t *testing.T) {
	stubCrashOutput(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxSpoolFiles+3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("crash-%02d.dump", i))
		mustWrite(t, p, "old")
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}

	s, err := Install(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, i := range []int{0, 1, 2} {
		p := filepath.Join(dir, fmt.Sprintf("crash-%02d.dump", i))
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("oldest dump %s not pruned: %v", p, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, e := range entries {
		if isDumpName(e.Name()) {
			got++
		}
	}
	if want := maxSpoolFiles + 1; got != want {
		t.Fatalf("dump count = %d, want %d", got, want)
	}
}

func TestPendingReadsNonEmptyAndPrunesEmpty(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "crash-a.dump"), "boom")
	mustWrite(t, filepath.Join(dir, "panic-b.dump"), "recovered")
	mustWrite(t, filepath.Join(dir, "crash-empty.dump"), "")
	mustWrite(t, filepath.Join(dir, "notes.txt"), "ignore me")

	dumps, err := Pending(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dumps) != 2 {
		t.Fatalf("Pending returned %d dumps, want 2", len(dumps))
	}
	if _, err := os.Stat(filepath.Join(dir, "crash-empty.dump")); !os.IsNotExist(err) {
		t.Fatalf("empty dump not pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
}

func TestReportPendingWritesAndRemoves(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "crash-a.dump"), "boom line")

	var buf bytes.Buffer
	n, err := ReportPending(dir, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reported %d dumps, want 1", n)
	}
	if !strings.Contains(buf.String(), "boom line") {
		t.Fatalf("output missing dump contents: %q", buf.String())
	}
	dumps, err := Pending(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dumps) != 0 {
		t.Fatalf("reported dump not removed: %d left", len(dumps))
	}
}

func TestRecoverWritesPanicReport(t *testing.T) {
	stubCrashOutput(t)
	dir := t.TempDir()
	s, err := Install(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	func() {
		defer func() { _ = recover() }() // swallow Recover's re-panic
		defer Recover()
		panic("recovered-boom")
	}()

	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("recovered-boom")) {
		t.Fatalf("panic report missing message:\n%s", data)
	}
}

func TestDefaultDirUnderCache(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dir, filepath.Join("pleno-dlp", "crashes")) {
		t.Fatalf("DefaultDir() = %q, want .../pleno-dlp/crashes", dir)
	}
}
