package crash

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCaptureHelper(t *testing.T, mode, dir string, disabled bool) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	disable := "0"
	if disabled {
		disable = "1"
	}
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, "CRASH_TEST_DIR="+dir, EnvDisable+"="+disable, "GOTRACEBACK=single", "GODEBUG=", "GORACE=exitcode=66")
	out, err := cmd.CombinedOutput()
	want := 2
	switch mode {
	case "clean":
		want = 0
	case "exit3":
		want = 3
	}
	if want == 0 {
		if err != nil {
			t.Fatalf("helper: %v\n%s", err, out)
		}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != want {
			t.Fatalf("helper: %v, want exit %d\n%s", err, want, out)
		}
	}
	return out
}

func TestRuntimeCapturesFatalPaths(t *testing.T) {
	for mode, message := range map[string]string{"panic": "boom for alice@example.com", "goroutine": "goroutine boom", "fatal": "fatal error: sync: unlock of unlocked mutex"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			runCaptureHelper(t, mode, dir, false)
			dumps, err := Pending(dir)
			if err != nil || len(dumps) != 1 {
				t.Fatalf("Pending = %v, %v", dumps, err)
			}
			if !bytes.Contains(dumps[0].Data, []byte(message)) || !bytes.Contains(dumps[0].Data, []byte("goroutine")) {
				t.Fatalf("missing runtime dump: %s", dumps[0].Data)
			}
		})
	}
}

func TestRuntimeIgnoresNonCrashOutput(t *testing.T) {
	for _, mode := range []string{"clean", "exit2", "exit3"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			runCaptureHelper(t, mode, dir, false)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("normal exit left spools: %v, %v", entries, err)
			}
		})
	}
}

func TestCaptureDisabled(t *testing.T) {
	t.Setenv(EnvDisable, "1")
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := Install(CaptureConfig{Dir: dir})
	if err != nil || s.Path() != "" || s.Dir() != "" {
		t.Fatalf("disabled install: %+v %v", s, err)
	}
	s.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("disabled capture created directory: %v", err)
	}
	t.Setenv(EnvDisable, "0")
	s, err = Install(CaptureConfig{Dir: dir, Disabled: true})
	if err != nil || s.Path() != "" {
		t.Fatalf("config disabled: %+v %v", s, err)
	}
	runCaptureHelper(t, "goroutine", dir, true)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("disabled helper created directory: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	t.Setenv(EnvDisable, "0")
	dir := t.TempDir()
	t.Setenv(EnvCrashDir, dir)
	s, err := Install(CaptureConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if s.Dir() != dir || s.Path() == "" {
		t.Fatalf("session: %+v", s)
	}
	for path, perm := range map[string]os.FileMode{dir: 0o700, s.Path(): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != perm {
			t.Fatalf("permissions %s: %v %v", path, info, err)
		}
	}
	// Reporting or another install must not unlink a live scanner's empty file.
	if _, err := ReportPending(dir, io.Discard); err != nil {
		t.Fatal(err)
	}
	pruneDumps(dir, 1)
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatalf("live spool removed: %v", err)
	}
	if _, err := Install(CaptureConfig{Dir: dir}); err == nil {
		t.Fatal("second active session accepted")
	}
	s.Close()
	s.Close()
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatalf("empty spool survived: %v", err)
	}
	// SetCrashOutput may be installed repeatedly, and Close releases its FD.
	again, err := Install(CaptureConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}

func TestRecoverPreservesDump(t *testing.T) {
	t.Setenv(EnvDisable, "0")
	s, err := Install(CaptureConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	func() {
		defer func() {
			if got := recover(); got != "recovered-boom" {
				t.Fatalf("panic = %v", got)
			}
		}()
		defer Recover()
		panic("recovered-boom")
	}()
	s.Close()
	data, err := os.ReadFile(s.Path())
	if err != nil || !bytes.Contains(data, []byte("recovered-boom")) {
		t.Fatalf("report = %s, %v", data, err)
	}
}

func writeDump(t *testing.T, dir, name, data string, mod time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPendingAndPruning(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxSpoolFiles+3; i++ {
		writeDump(t, dir, fmt.Sprintf("crash-%02d.dump", i), "boom", base.Add(time.Duration(i)*time.Minute))
	}
	empty := writeDump(t, dir, "crash-live.dump", "", base)
	unrelated := writeDump(t, dir, "notes.txt", "ignore", base)
	// Spool enumeration must not read symlinks or delete their targets.
	if err := os.Symlink(unrelated, filepath.Join(dir, "crash-link.dump")); err != nil {
		t.Fatal(err)
	}
	pruneDumps(dir, maxSpoolFiles)
	dumps, err := Pending(dir)
	if err != nil || len(dumps) != maxSpoolFiles {
		t.Fatalf("Pending = %v, %v", dumps, err)
	}
	if filepath.Base(dumps[0].Path) != "crash-03.dump" {
		t.Fatalf("oldest dump not pruned: %s", dumps[0].Path)
	}
	for _, path := range []string{empty, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	// Ordering uses modification time, not CreateTemp's random suffix.
	writeDump(t, dir, "panic-z.dump", "older", base.Add(-time.Hour))
	dumps, err = Pending(dir)
	if err != nil || filepath.Base(dumps[0].Path) != "panic-z.dump" {
		t.Fatalf("order = %v, %v", dumps, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type shortWriter struct{ calls int }

func (w *shortWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 2 {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestReportPending(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "crash-a.dump", "boom line", time.Now())
	for _, w := range []io.Writer{failingWriter{}, &shortWriter{}} {
		if n, err := ReportPending(dir, w); err == nil || n != 0 {
			t.Fatalf("failed writer: %d, %v", n, err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unreported dump lost: %v", err)
		}
	}
	var buf bytes.Buffer
	if n, err := ReportPending(dir, &buf); err != nil || n != 1 {
		t.Fatalf("report: %d, %v", n, err)
	}
	if !strings.Contains(buf.String(), "boom line\n") {
		t.Fatalf("output: %s", &buf)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reported dump retained: %v", err)
	}
}

func TestCaptureDirectoryErrors(t *testing.T) {
	t.Setenv(EnvDisable, "0")
	dir := t.TempDir()
	path := writeDump(t, dir, "file", "not a directory", time.Now())
	if _, err := Install(CaptureConfig{Dir: path}); err == nil {
		t.Fatal("Install succeeded on file")
	}
	if _, err := Pending(path); err == nil {
		t.Fatal("Pending succeeded on file")
	}
	if dumps, err := Pending(filepath.Join(dir, "missing")); err != nil || len(dumps) != 0 {
		t.Fatalf("missing spool: %v %v", dumps, err)
	}
}

func TestDefaultCaptureDir(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir, err := DefaultDir()
	if err != nil || !strings.HasSuffix(dir, filepath.Join("pleno-dlp", "crashes")) {
		t.Fatalf("DefaultDir: %s %v", dir, err)
	}
}
