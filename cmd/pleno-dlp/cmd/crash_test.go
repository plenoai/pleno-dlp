package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// TestDescribeInvocation_RecordsPreSubcommandFlags is the #516 regression:
// a root/persistent flag given *before* the subcommand must be recorded just
// like one after it, while flag values and positional arguments never appear.
func TestDescribeInvocation_RecordsPreSubcommandFlags(t *testing.T) {
	resetCommandFlags(t)

	args := []string{"--crash-report", "/tmp/crash.json", "scan", "filesystem", "/home/alice/secret", "--format=json"}
	command, flags := DescribeInvocation(args)
	if command != "scan filesystem" {
		t.Fatalf("DescribeInvocation(%q) command = %q, want %q", args, command, "scan filesystem")
	}
	joined := strings.Join(flags, " ")
	for _, want := range []string{"crash-report", "format"} {
		if !strings.Contains(joined, want) {
			t.Errorf("DescribeInvocation(%q) flags = %v; missing %q", args, flags, want)
		}
	}
	for _, leak := range []string{"crash.json", "/tmp", "alice", "secret"} {
		if strings.Contains(joined, leak) {
			t.Errorf("DescribeInvocation(%q) flags = %v; leaked value %q", args, flags, leak)
		}
	}
}

func TestCrashReport_WriteFileSchemaAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "crash.json")

	want := crash.Build(crash.KindCrash, "panic: boom", "goroutine [running]:\n",
		crash.Meta{Version: "t"}, &crash.Redactor{}, time.Now())
	if err := crash.WriteFile(path, want); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("report perms = %o, want 600", got)
	}

	got, raw, err := crash.ReadReport(path)
	if err != nil {
		t.Fatalf("report is not a valid crash report: %v", err)
	}
	if got.Schema != crash.Schema || got.Kind != crash.KindCrash {
		t.Errorf("schema=%q kind=%q, want %q/%q", got.Schema, got.Kind, crash.Schema, crash.KindCrash)
	}
	if !strings.Contains(got.Message, "boom") || got.Stack == "" {
		t.Errorf("report missing panic/stack: %+v", got)
	}
	if canonical, _ := crash.Encode(want); string(canonical) != string(raw) {
		t.Errorf("on-disk bytes differ from the canonical encoding:\n%s", raw)
	}
}

func TestHandleCrash_WritesReportAndReturnsError(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "crash.json")
	crashReportPath = path
	t.Cleanup(func() { crashReportPath = "" })

	err := handleCrash("kaboom")
	if err == nil {
		t.Fatal("handleCrash must return a non-nil error so main exits non-zero")
	}
	if !strings.Contains(err.Error(), "kaboom") {
		t.Errorf("returned error %v should include the panic value", err)
	}
	got, _, rerr := crash.ReadReport(path)
	if rerr != nil {
		t.Fatalf("crash report not written or not readable: %v", rerr)
	}
	if got.Kind != crash.KindCrash {
		t.Errorf("kind = %q, want %q", got.Kind, crash.KindCrash)
	}
	if !strings.Contains(got.Message, "kaboom") {
		t.Errorf("message = %q, want the panic value", got.Message)
	}
}

// TestCrashReport_EndToEnd drives the real binary so Execute's recovery, the
// persistent flag binding, and the on-disk report are exercised together. The
// flag is given *before* the subcommand to cover the #516 pre-subcommand case
// through an actual cobra parse.
func TestCrashReport_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the pleno-dlp binary")
	}
	if hooksGitTestBinary == "" {
		t.Fatal("pleno-dlp test binary was not built")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "crash.json")

	c := exec.Command(hooksGitTestBinary, "--crash-report", path, "telemetry", "crash-test")
	c.Env = append(os.Environ(), "PLENO_DLP_TELEMETRY_DIR="+dir, "PLENO_DLP_CRASH_REPORTS=0", crash.EnvCrashDir+"="+filepath.Join(dir, "raw"), crash.EnvDisable+"=0", crash.EnvReport+"=0")
	out, err := c.CombinedOutput()
	if err == nil {
		t.Fatalf("crash-test should exit non-zero; output:\n%s", out)
	}

	got, _, rerr := crash.ReadReport(path)
	if rerr != nil {
		t.Fatalf("crash report not written: %v\noutput:\n%s", rerr, out)
	}
	if got.Kind != crash.KindCrash {
		t.Errorf("kind = %q, want %q", got.Kind, crash.KindCrash)
	}
	if got.Command != "telemetry crash-test" {
		t.Errorf("command = %q, want %q", got.Command, "telemetry crash-test")
	}
	if !strings.Contains(strings.Join(got.Flags, " "), "crash-report") {
		t.Errorf("flags %v should record the pre-subcommand flag", got.Flags)
	}
	if !strings.Contains(got.Message, "crash-test") {
		t.Errorf("message = %q, want the crash-test panic", got.Message)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "raw")); err != nil || len(entries) != 0 {
		t.Fatalf("contained panic left raw spools: %v %v", entries, err)
	}
	// Offline guarantee: the local report must not be spooled or sent.
	if _, err := os.Stat(filepath.Join(dir, "crash")); !os.IsNotExist(err) {
		t.Errorf("--crash-report must not spool a telemetry report; stat err = %v", err)
	}
}

func TestHandleCrash_DisabledRepanics(t *testing.T) {
	resetCommandFlags(t)
	crashReportPath = ""
	t.Cleanup(func() { crashReportPath = "" })

	defer func() {
		if r := recover(); r != "kaboom" {
			t.Errorf("disabled crash reporting must re-panic with the original value; got %v", r)
		}
	}()
	_ = handleCrash("kaboom")
	t.Fatal("handleCrash should have re-panicked")
}

// Exercise startup, fatal capture, and readback through the production main.
func TestRuntimeCrashCapture_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the pleno-dlp binary")
	}
	if hooksGitTestBinary == "" {
		t.Fatal("pleno-dlp test binary was not built")
	}
	for _, tc := range []struct{ mode, enabled string }{{"goroutine", "0"}, {"goroutine", "1"}, {"main", "0"}} {
		t.Run(tc.mode+"-upload-opt-in-"+tc.enabled, func(t *testing.T) {
			dir := t.TempDir()
			rawDir := filepath.Join(dir, "raw")
			env := append(os.Environ(), crash.EnvDir+"="+dir, crash.EnvCrashDir+"="+rawDir,
				crash.EnvReports+"="+tc.enabled, crash.EnvDisable+"=0", crash.EnvReport+"=0", "GOTRACEBACK=single")
			args := []string{"telemetry", "crash-test"}
			if tc.mode == "goroutine" {
				args = append(args, "--goroutine")
			}
			c := exec.Command(hooksGitTestBinary, args...)
			c.Env = env
			out, err := c.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
				t.Fatalf("crash exit: %v\n%s", err, out)
			}
			dumps, err := crash.Pending(rawDir)
			if err != nil || len(dumps) != 1 {
				t.Fatalf("Pending: %v %v\n%s", dumps, err, out)
			}
			if !strings.Contains(string(dumps[0].Data), "pleno-dlp telemetry crash-test") {
				t.Fatalf("missing panic: %s", dumps[0].Data)
			}
			// A normal invocation must retain earlier dumps unless explicitly asked.
			c = exec.Command(hooksGitTestBinary, "telemetry", "status")
			c.Env = env
			out, err = c.CombinedOutput()
			if err != nil {
				t.Fatalf("status: %v\n%s", err, out)
			}
			if strings.Contains(string(out), "--- crash report") {
				t.Fatalf("reported without opt-in: %s", out)
			}
			if _, err := os.Stat(dumps[0].Path); err != nil {
				t.Fatal(err)
			}
			c = exec.Command(hooksGitTestBinary, "telemetry", "status")
			c.Env = append(env, crash.EnvReport+"=1")
			out, err = c.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "reported 1 previous crash dump(s)") {
				t.Fatalf("readback: %v\n%s", err, out)
			}
			entries, err := os.ReadDir(rawDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("readback/normal exit left files: %v %v", entries, err)
			}
		})
	}
}

func TestRuntimeCaptureStartupFailure_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the pleno-dlp binary")
	}
	if hooksGitTestBinary == "" {
		t.Fatal("pleno-dlp test binary was not built")
	}
	dir := t.TempDir()
	invalid := filepath.Join(dir, "file")
	if err := os.WriteFile(invalid, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command(hooksGitTestBinary, "telemetry", "status")
	c.Env = append(os.Environ(), crash.EnvDir+"="+dir, crash.EnvCrashDir+"="+invalid, crash.EnvDisable+"=0", crash.EnvReports+"=0")
	out, err := c.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "warning: crash capture disabled:") || !strings.Contains(string(out), "crash reports: disabled") {
		t.Fatalf("capture failure blocked CLI: %v\n%s", err, out)
	}
}

func TestRuntimeCaptureErrorExit_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the pleno-dlp binary")
	}
	if hooksGitTestBinary == "" {
		t.Fatal("pleno-dlp test binary was not built")
	}
	dir := t.TempDir()
	c := exec.Command(hooksGitTestBinary, "--definitely-invalid-flag")
	c.Env = append(os.Environ(), crash.EnvCrashDir+"="+dir, crash.EnvDisable+"=0", crash.EnvReport+"=0")
	out, err := c.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Fatalf("error exit: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("error exit left spools: %v %v", entries, err)
	}
}

func TestRuntimeCaptureDisabledReadback_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the pleno-dlp binary")
	}
	if hooksGitTestBinary == "" {
		t.Fatal("pleno-dlp test binary was not built")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "crash-old.dump")
	if err := os.WriteFile(path, []byte("private old crash"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command(hooksGitTestBinary, "telemetry", "status")
	c.Env = append(os.Environ(), crash.EnvDir+"="+dir, crash.EnvCrashDir+"="+dir, crash.EnvDisable+"=1", crash.EnvReport+"=1", crash.EnvReports+"=0")
	out, err := c.CombinedOutput()
	if err != nil || strings.Contains(string(out), "private old crash") {
		t.Fatalf("disabled readback: %v\n%s", err, out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("disabled readback removed dump: %v", err)
	}
}
