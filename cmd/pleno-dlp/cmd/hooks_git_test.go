package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const fixtureAWSKey = "AKIA1234567890ABCDEF"

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	runGit(t, dir, "config", "core.hooksPath", ".git/hooks")
	return dir
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func TestStagedDiffForScan(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/a.env b/a.env",
		"index 111..222 100644",
		"--- a/a.env",
		"+++ b/a.env",
		"@@ -1,3 +1,3 @@",
		" keep=1",
		"-OLD_SECRET=removed",
		"+NEW=added",
		"++++plus-prefixed",
		"--- not a header inside a hunk",
		"\\ No newline at end of file",
		"diff --git a/b.txt b/b.txt",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/b.txt",
		"@@ -0,0 +10,1 @@",
		"+hello",
		"",
	}, "\n")
	buf, origins := stagedDiffForScan([]byte(diff))
	want := "+++ b/a.env\nNEW=added\n+++plus-prefixed\n+++ b/b.txt\nhello\n"
	if string(buf) != want {
		t.Fatalf("buffer:\n%q\nwant:\n%q", buf, want)
	}
	wantOrigins := []diffOrigin{{"a.env", 0}, {"a.env", 2}, {"a.env", 3}, {"b.txt", 0}, {"b.txt", 10}}
	if len(origins) != len(wantOrigins) {
		t.Fatalf("origins = %v, want %v", origins, wantOrigins)
	}
	for i := range wantOrigins {
		if origins[i] != wantOrigins[i] {
			t.Errorf("origins[%d] = %v, want %v", i, origins[i], wantOrigins[i])
		}
	}
	off := strings.Index(string(buf), "hello")
	if o, ok := originAt(buf, origins, &off); !ok || o != (diffOrigin{"b.txt", 10}) {
		t.Errorf("originAt(hello) = %v,%v", o, ok)
	}
	if _, ok := originAt(buf, origins, nil); ok {
		t.Error("originAt(nil) should be !ok")
	}
}

func TestFindingsAtOrAbove(t *testing.T) {
	recs := []hookFinding{
		{Detector: "A", Severity: "medium"},
		{Detector: "B", Severity: "high"},
		{Detector: "C", Severity: "critical"},
		{Detector: "D", Severity: "critical", SuppressedBy: "allowlist"},
		{Detector: "E", Severity: "info"},
	}
	cases := map[string]int{"any": 4, "info": 4, "medium": 3, "high": 2, "critical": 1}
	for level, want := range cases {
		th, err := parseFailOn(level)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(findingsAtOrAbove(recs, th)); got != want {
			t.Errorf("fail-on %s: %d findings, want %d", level, got, want)
		}
	}
	if severityRank("bogus") != detectors.SeverityUnknown {
		t.Error("unknown severity string should rank Unknown")
	}
}

func TestMaskRedacted(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "(redacted)",
		"AKIA...":                "AKIA...",
		"AKIA1234567890ABCDEF":   "AKIA12...",
		"sk_live_abcdefghijk...": "sk_liv...",
	} {
		if got := maskRedacted(in); got != want {
			t.Errorf("maskRedacted(%q) = %q, want %q", in, got, want)
		}
	}
}

func withFakeStagedDiff(t *testing.T, diff string, err error) {
	t.Helper()
	orig := collectDiffForScanFunc
	collectDiffForScanFunc = func(context.Context, string, bool) ([]byte, []diffOrigin, error) {
		if err != nil {
			return nil, nil, err
		}
		buf, origins := stagedDiffForScan([]byte(diff))
		return buf, origins, nil
	}
	t.Cleanup(func() { collectDiffForScanFunc = orig })
}

// withFakeStagedScan replaces protect's in-process scan for the git hook.
func withFakeStagedScan(t *testing.T, fn func(data []byte) ([]hookFinding, error)) {
	t.Helper()
	orig := stagedScanFunc
	stagedScanFunc = func(_ *cobra.Command, data []byte) ([]hookFinding, error) { return fn(data) }
	t.Cleanup(func() { stagedScanFunc = orig })
}

func runHooksGit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs(append([]string{"hooks", "run", "git"}, args...))
	err := Root.Execute()
	return out.String(), err
}

const leakDiff = "diff --git a/leak.env b/leak.env\n--- /dev/null\n+++ b/leak.env\n@@ -0,0 +1,2 @@\n+# config\n+AWS_ACCESS_KEY_ID=" + fixtureAWSKey + "\n"

func TestRunHookGit_BlocksAtThreshold(t *testing.T) {
	resetCommandFlags(t)
	withFakeStagedDiff(t, leakDiff, nil)
	withFakeStagedScan(t, func(data []byte) ([]hookFinding, error) {
		start := bytes.Index(data, []byte(fixtureAWSKey))
		return []hookFinding{
			{Detector: "AWS", Severity: "high", Redacted: fixtureAWSKey, Start: &start},
			{Detector: "Generic", Severity: "medium", Redacted: "x..."},
		}, nil
	})
	out, err := runHooksGit(t)
	if !IsFindingsError(err) {
		t.Fatalf("err = %v, want findings sentinel; out:\n%s", err, out)
	}
	if strings.Contains(out, fixtureAWSKey) {
		t.Errorf("stderr leaks the unmasked secret:\n%s", out)
	}
	for _, want := range []string{"AWS", "AKIA12...", "leak.env:2", "blocked commit (1 findings at or above high)", "git commit --no-verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Generic") {
		t.Errorf("medium finding should be below the high gate:\n%s", out)
	}
}

func TestRunHookGit_FailOnCriticalAllowsHigh(t *testing.T) {
	resetCommandFlags(t)
	withFakeStagedDiff(t, leakDiff, nil)
	withFakeStagedScan(t, func([]byte) ([]hookFinding, error) {
		return []hookFinding{{Detector: "AWS", Severity: "high"}}, nil
	})
	if out, err := runHooksGit(t, "--fail-on", "critical"); err != nil || out != "" {
		t.Fatalf("want silent pass, got err=%v out=%q", err, out)
	}
}

func TestRunHookGit_EmptyDiffSilent(t *testing.T) {
	resetCommandFlags(t)
	withFakeStagedDiff(t, "", nil)
	withFakeStagedScan(t, func([]byte) ([]hookFinding, error) {
		t.Error("scan should not run on an empty diff")
		return nil, nil
	})
	if out, err := runHooksGit(t); err != nil || out != "" {
		t.Fatalf("want silent pass, got err=%v out=%q", err, out)
	}
}

func TestRunHookGit_FailsOpenOnPlumbingErrors(t *testing.T) {
	resetCommandFlags(t)
	withFakeStagedDiff(t, "", errors.New("not a git repository"))
	out, err := runHooksGit(t)
	if err != nil || !strings.Contains(out, "allowing commit") {
		t.Fatalf("git failure: err=%v out=%q", err, out)
	}

	resetCommandFlags(t)
	withFakeStagedDiff(t, leakDiff, nil)
	withFakeStagedScan(t, func([]byte) ([]hookFinding, error) { return nil, os.ErrPermission })
	out, err = runHooksGit(t)
	if err != nil || !strings.Contains(out, "allowing commit") {
		t.Fatalf("scan failure: err=%v out=%q", err, out)
	}
}

func TestStagedDiffForScan_NoAdditions(t *testing.T) {
	diff := "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,2 +1,1 @@\n unchanged\n-removed\n"
	if buf, origins := stagedDiffForScan([]byte(diff)); buf != nil || origins != nil {
		t.Errorf("diff without additions should yield nothing, got %q %v", buf, origins)
	}
}

func TestRunHookGit_RejectsBadFailOn(t *testing.T) {
	resetCommandFlags(t)
	withFakeStagedDiff(t, leakDiff, nil)
	if _, err := runHooksGit(t, "--fail-on", "severe"); err == nil || IsFindingsError(err) {
		t.Fatalf("want a usage error, got %v", err)
	}
}

func TestHooksFailOnRejectedForAgentTargets(t *testing.T) {
	resetCommandFlags(t)
	chdir(t, t.TempDir())
	Root.SetOut(&bytes.Buffer{})
	Root.SetArgs([]string{"hooks", "install", "claude-code", "--fail-on", "critical"})
	if err := Root.Execute(); err == nil {
		t.Fatal("--fail-on on claude-code should be rejected")
	}
}

func executeHooks(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetCommandFlags(t)
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs(append([]string{"hooks"}, args...))
	err := Root.Execute()
	return out.String(), err
}

func TestHooksInstallGit_WritesIdempotentAndUninstalls(t *testing.T) {
	dir := initGitRepo(t)
	chdir(t, dir)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")

	out, err := executeHooks(t, "install", "git", "--fail-on", "medium")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if !strings.Contains(out, hook) && !strings.Contains(out, filepath.Base(filepath.Dir(hook))) {
		t.Errorf("install should print the resolved path:\n%s", out)
	}
	body, err := os.ReadFile(hook)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), gitHookMarker) || !strings.Contains(string(body), "hooks run git --fail-on 'medium'") {
		t.Errorf("unexpected hook body:\n%s", body)
	}
	if fi, _ := os.Stat(hook); fi.Mode()&0o111 == 0 {
		t.Error("hook is not executable")
	}

	out, err = executeHooks(t, "install", "git", "--fail-on", "medium")
	if err != nil || !strings.Contains(out, "already installed") {
		t.Fatalf("reinstall: err=%v out=%s", err, out)
	}
	out, err = executeHooks(t, "install", "git")
	if err != nil || !strings.HasPrefix(out, "updated") {
		t.Fatalf("threshold change should update: err=%v out=%s", err, out)
	}

	if out, err = executeHooks(t, "uninstall", "git"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if _, err := os.Stat(hook); !os.IsNotExist(err) {
		t.Errorf("hook should be removed, stat err = %v", err)
	}
	if out, err = executeHooks(t, "uninstall", "git"); err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("second uninstall: err=%v out=%s", err, out)
	}
}

func TestHooksInstallGit_RefusesForeignHook(t *testing.T) {
	dir := initGitRepo(t)
	chdir(t, dir)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := "#!/bin/sh\necho mine\n"
	if err := os.WriteFile(hook, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := executeHooks(t, "install", "git"); err == nil || !strings.Contains(err.Error(), "hooks print git") {
		t.Fatalf("install over a foreign hook should refuse and point at print, got %v", err)
	}
	if out, err := executeHooks(t, "uninstall", "git"); err != nil || !strings.Contains(out, "untouched") {
		t.Fatalf("uninstall of foreign hook: err=%v out=%s", err, out)
	}
	if got, _ := os.ReadFile(hook); string(got) != foreign {
		t.Errorf("foreign hook modified:\n%s", got)
	}
}

func TestHooksPrintGit(t *testing.T) {
	out, err := executeHooks(t, "print", "git", "--fail-on", "critical")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/sh\n", gitHookMarker, "command -v pleno-dlp", "exit 0", "exec pleno-dlp hooks run git --fail-on 'critical'"} {
		if !strings.Contains(out, want) {
			t.Errorf("print output missing %q:\n%s", want, out)
		}
	}
	if _, err := executeHooks(t, "print", "cursor"); err == nil {
		t.Error("print cursor should be rejected")
	}
}

// TestHooksPrintGit_DegradesWithoutBinary runs the printed script with an
// empty PATH-equivalent and asserts it skips instead of failing the commit.
func TestHooksPrintGit_DegradesWithoutBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX sh script")
	}
	out, err := executeHooks(t, "print", "git")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "pre-commit")
	if err := os.WriteFile(script, []byte(out), 0o755); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/bin/sh", script)
	c.Env = []string{"PATH=" + t.TempDir()}
	res, err := c.CombinedOutput()
	if err != nil || !strings.Contains(string(res), "skipping") {
		t.Fatalf("err=%v out=%s", err, res)
	}
}

// TestHookGitEndToEnd builds the real binary, installs the hook into a
// fresh repo, and drives `git commit` so the whole chain — git env,
// diff transform, `scan stdin` subprocess, exit-code mapping in main.go —
// is exercised.
func TestHookGitEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the pleno-dlp binary")
	}
	bin := filepath.Join(t.TempDir(), "pleno-dlp")
	build := exec.Command("go", "build", "-o", bin, "github.com/plenoai/pleno-dlp/cmd/pleno-dlp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	dir := initGitRepo(t)
	if out, err := exec.Command(bin, "-h").CombinedOutput(); err != nil {
		t.Fatalf("binary smoke: %v\n%s", err, out)
	}
	install := exec.Command(bin, "hooks", "install", "git")
	install.Dir = dir
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}

	commit := func(name, content string) (string, int) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		runGit(t, dir, "add", name)
		c := exec.Command("git", "commit", "-q", "-m", name)
		c.Dir = dir
		out, err := c.CombinedOutput()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(out), 0
	}

	if out, code := commit("README.md", "hello world\n"); code != 0 {
		t.Fatalf("clean commit blocked (exit %d):\n%s", code, out)
	}

	out, code := commit("leak.env", "AWS_ACCESS_KEY_ID="+fixtureAWSKey+"\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\n")
	if code == 0 {
		t.Fatalf("commit with a staged AWS key should be blocked:\n%s", out)
	}
	if !strings.Contains(out, "blocked commit") || !strings.Contains(out, "leak.env:1") {
		t.Errorf("unexpected hook output:\n%s", out)
	}
	if strings.Contains(out, fixtureAWSKey) {
		t.Errorf("hook output leaks the raw key:\n%s", out)
	}

	// Direct run: the sentinel maps to exit 1 in main.go.
	run := exec.Command(bin, "hooks", "run", "git")
	run.Dir = dir
	err := run.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("hooks run git exit = %v, want 1", err)
	}
}
