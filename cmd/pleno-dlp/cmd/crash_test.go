package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDescribeInvocation_RecordsFlagsOnBothSidesOfSubcommand is the #497
// regression: a root/persistent flag given *before* the subcommand must be
// recorded just like one after it, while flag values never appear.
func TestDescribeInvocation_RecordsFlagsOnBothSidesOfSubcommand(t *testing.T) {
	resetCommandFlags(t)

	args := []string{"--crash-report", "/tmp/crash.json", "scan", "github", "--repo", "org/repo", "--format=json"}
	got := DescribeInvocation(args)

	for _, want := range []string{"pleno-dlp", "scan", "github", "--crash-report", "--repo", "--format"} {
		if !strings.Contains(got, want) {
			t.Errorf("DescribeInvocation(%q) = %q; missing %q", args, got, want)
		}
	}
	for _, leak := range []string{"/tmp/crash.json", "org/repo"} {
		if strings.Contains(got, leak) {
			t.Errorf("DescribeInvocation(%q) = %q; leaked value %q", args, got, leak)
		}
	}
}

// TestDescribeInvocation_RootFlagOnly guards the degenerate case: a
// pre-subcommand flag with no subcommand still appears (and the value of a
// value-taking flag is skipped, not mistaken for a subcommand).
func TestDescribeInvocation_RootFlagOnly(t *testing.T) {
	resetCommandFlags(t)

	got := DescribeInvocation([]string{"--crash-report", "out.json", "--version"})
	for _, want := range []string{"pleno-dlp", "--crash-report", "--version"} {
		if !strings.Contains(got, want) {
			t.Errorf("DescribeInvocation = %q; missing %q", got, want)
		}
	}
	if strings.Contains(got, "out.json") {
		t.Errorf("DescribeInvocation = %q; leaked flag value", got)
	}
}

func TestDescribeInvocation_NoFlags(t *testing.T) {
	resetCommandFlags(t)

	got := DescribeInvocation([]string{"scan", "filesystem", "."})
	if got != "pleno-dlp scan filesystem" {
		t.Errorf("DescribeInvocation = %q, want %q", got, "pleno-dlp scan filesystem")
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
		t.Errorf("returned error %q should include the panic value", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("crash report not written: %v", statErr)
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
