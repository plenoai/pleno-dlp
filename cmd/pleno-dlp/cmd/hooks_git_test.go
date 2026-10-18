package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hooksGitTestBinary is the real pleno-dlp binary, built exactly once for
// the whole package in TestMain (#497). The git hook can only be exercised
// end-to-end by git itself: `git commit` spawns the generated pre-commit
// wrapper, which execs this binary as `hooks run git`. Building it per test
// paid the compile cost over and over; TestMain pays it once.
var hooksGitTestBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pleno-dlp-hooks-git-")
	if err != nil {
		panic("hooks_git: create temp dir: " + err.Error())
	}
	bin := filepath.Join(dir, "pleno-dlp")
	build := exec.Command("go", "build", "-o", bin, "github.com/plenoai/pleno-dlp/cmd/pleno-dlp")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		_ = os.RemoveAll(dir)
		panic("hooks_git: build pleno-dlp: " + err.Error())
	}
	hooksGitTestBinary = bin

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	runGit(t, dir, "config", "commit.gpgsign", "false")
	// Pin the hooks path so a global core.hooksPath in the test
	// environment cannot silently bypass the hook we install.
	runGit(t, dir, "config", "core.hooksPath", ".git/hooks")
}

func installGitHookBinary(t *testing.T, dir string) {
	t.Helper()
	c := exec.Command(hooksGitTestBinary, "hooks", "install", "git")
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("hooks install git: %v\n%s", err, out)
	}
}

// TestHooksGit_EndToEnd_BlocksCommitOnFinding stages a secret and asserts
// that a real `git commit` is aborted by the installed hook, with a message
// that points back at pleno-dlp.
func TestHooksGit_EndToEnd_BlocksCommitOnFinding(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	initGitRepo(t, dir)
	installGitHookBinary(t, dir)

	if err := writeFile(filepath.Join(dir, "leak.env"), "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")

	commit := exec.Command("git", "commit", "-m", "leak")
	commit.Dir = dir
	out, err := commit.CombinedOutput()
	if err == nil {
		t.Fatalf("commit with a staged secret unexpectedly succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "pleno-dlp") {
		t.Errorf("commit failure did not mention pleno-dlp:\n%s", out)
	}
}

// TestHooksGit_EndToEnd_AllowsCleanCommit is the other half of the contract:
// a commit with no findings must go through untouched.
func TestHooksGit_EndToEnd_AllowsCleanCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	initGitRepo(t, dir)
	installGitHookBinary(t, dir)

	if err := writeFile(filepath.Join(dir, "clean.txt"), "nothing interesting here\n"); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "clean.txt")

	commit := exec.Command("git", "commit", "-m", "clean")
	commit.Dir = dir
	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("clean commit was blocked: %v\n%s", err, out)
	}
}

// TestHooksGit_UninstallRemovesOnlyOurHook checks that uninstall deletes the
// script it wrote and refuses to touch a pre-commit hook it does not own.
func TestHooksGit_UninstallRemovesOnlyOurHook(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	initGitRepo(t, dir)
	installGitHookBinary(t, dir)

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	uninstall := exec.Command(hooksGitTestBinary, "hooks", "uninstall", "git")
	uninstall.Dir = dir
	if out, err := uninstall.CombinedOutput(); err != nil {
		t.Fatalf("hooks uninstall git: %v\n%s", err, out)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Errorf("pre-commit hook still present after uninstall: %v", err)
	}

	// A foreign pre-commit hook must survive uninstall.
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho not-ours\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	uninstall = exec.Command(hooksGitTestBinary, "hooks", "uninstall", "git")
	uninstall.Dir = dir
	if out, err := uninstall.CombinedOutput(); err == nil {
		t.Fatalf("uninstall should refuse a foreign pre-commit hook; output:\n%s", out)
	}
	if _, err := os.Stat(hookPath); err != nil {
		t.Errorf("foreign pre-commit hook was removed: %v", err)
	}
}
