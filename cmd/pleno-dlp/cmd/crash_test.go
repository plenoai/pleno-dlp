package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// TestInvocationDescription_OneLine pins the crash report's invocation text:
// command path, then each flag with its -- prefix, and no values.
func TestInvocationDescription_OneLine(t *testing.T) {
	resetCommandFlags(t)

	got := invocationDescription([]string{"--crash-report", "out.json", "scan", "filesystem", "--format=json"})
	for _, want := range []string{"pleno-dlp", "scan filesystem", "--crash-report", "--format"} {
		if !strings.Contains(got, want) {
			t.Errorf("invocationDescription = %q; missing %q", got, want)
		}
	}
	if strings.Contains(got, "out.json") {
		t.Errorf("invocationDescription = %q; leaked a flag value", got)
	}
}

func TestWriteCrashReport_SchemaAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "crash.json")

	want := newCrashReport("boom", "pleno-dlp --crash-report scan")
	if err := writeCrashReport(path, want); err != nil {
		t.Fatalf("writeCrashReport: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("report perms = %o, want 600", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var got crashReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, data)
	}
	if got.Schema != 1 {
		t.Errorf("schema = %d, want 1", got.Schema)
	}
	if got.Panic != "boom" {
		t.Errorf("panic = %q, want boom", got.Panic)
	}
	if got.Invocation != "pleno-dlp --crash-report scan" {
		t.Errorf("invocation = %q", got.Invocation)
	}
	if got.Stack == "" {
		t.Error("stack must not be empty")
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
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("crash report not written: %v", statErr)
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

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("crash report not written: %v\noutput:\n%s", rerr, out)
	}
	var got crashReport
	if jerr := json.Unmarshal(data, &got); jerr != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", jerr, data)
	}
	if !strings.Contains(got.Invocation, "--crash-report") {
		t.Errorf("invocation %q should record the pre-subcommand flag", got.Invocation)
	}
	if !strings.Contains(got.Panic, "crash-test") {
		t.Errorf("panic = %q, want the crash-test panic", got.Panic)
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
