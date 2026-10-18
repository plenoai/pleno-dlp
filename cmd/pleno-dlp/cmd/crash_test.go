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
	c.Env = append(os.Environ(), "PLENO_DLP_TELEMETRY_DIR="+dir, "PLENO_DLP_CRASH_REPORTS=0")
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
