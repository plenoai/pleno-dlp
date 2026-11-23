package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baselineFixtureRules = `[{"name":"Fixture Token","keywords":["FIXTURE_"],"regex":"FIXTURE_[A-Z]{20}","severity":"high"}]`

func runRootCapture(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	resetCommandFlagsNow()
	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetIn(strings.NewReader(stdin))
	Root.SetArgs(args)
	err := Root.Execute()
	return out.String(), errBuf.String(), err
}

// TestBaselineWorkflow covers create → --baseline suppression → a new
// finding still gating → update pruning a fixed secret, with paths stored
// relative to the scan root so the file is portable across checkouts.
func TestBaselineWorkflow(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	chdir(t, dir)
	rules := filepath.Join(t.TempDir(), "rules.json")
	mustWrite(t, rules, baselineFixtureRules)
	mustWrite(t, filepath.Join(dir, "src", "a.env"), "token=FIXTURE_ABCDEFGHIJKLMNOPQRST\n")

	report, stderr, err := runRootCapture(t, "", "scan", "--rules", rules, "--format", "json", "filesystem", ".")
	if !IsFindingsError(err) {
		t.Fatalf("seed scan should gate; err=%v stderr=%s", err, stderr)
	}
	if _, stderr, err := runRootCapture(t, report, "baseline", "create"); err != nil {
		t.Fatalf("baseline create: %v\n%s", err, stderr)
	}
	raw, err := os.ReadFile(filepath.Join(dir, defaultBaselinePath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"path": "src/a.env"`) || strings.Contains(string(raw), "ABCDEFGHIJKLMNOPQRST") {
		t.Fatalf("baseline must store a relative path and no raw secret:\n%s", raw)
	}
	if _, _, err := runRootCapture(t, report, "baseline", "create"); err == nil {
		t.Fatal("create must refuse to overwrite without --force")
	}

	_, stderr, err = runRootCapture(t, "", "scan", "--rules", rules, "--baseline", defaultBaselinePath, "filesystem", ".")
	if err != nil {
		t.Fatalf("baselined finding must exit 0; err=%v stderr=%s", err, stderr)
	}
	if !strings.Contains(stderr, "baseline: suppressed 1 finding(s)") {
		t.Fatalf("missing baseline suppression notice:\n%s", stderr)
	}

	mustWrite(t, filepath.Join(dir, "src", "b.env"), "token=FIXTURE_ZYXWVUTSRQPONMLKJIHG\n")
	out, stderr, err := runRootCapture(t, "", "scan", "--rules", rules, "--baseline", defaultBaselinePath, "--format", "json", "filesystem", ".")
	if !IsFindingsError(err) || !strings.Contains(out, "src/b.env") || strings.Contains(out, "src/a.env") {
		t.Fatalf("only the new finding must be reported; err=%v out=%s stderr=%s", err, out, stderr)
	}

	if err := os.Remove(filepath.Join(dir, "src", "a.env")); err != nil {
		t.Fatal(err)
	}
	report, _, _ = runRootCapture(t, "", "scan", "--rules", rules, "--format", "json", "filesystem", ".")
	if _, stderr, err := runRootCapture(t, report, "baseline", "update"); err != nil || !strings.Contains(stderr, "(+1, -1, 1 total)") {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
}

func TestScanSkipFlagsAndInlineAllow(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	mustWrite(t, rules, baselineFixtureRules)
	target := filepath.Join(dir, "x.env")
	mustWrite(t, target, "a=FIXTURE_ABCDEFGHIJKLMNOPQRST # pleno-dlp:allow\n")

	_, stderr, err := runRootCapture(t, "", "scan", "--rules", rules, "filesystem", target)
	if err != nil || !strings.Contains(stderr, "inline-allow: suppressed 1 finding(s)") {
		t.Fatalf("inline pragma must suppress; err=%v stderr=%s", err, stderr)
	}
	out, _, err := runRootCapture(t, "", "scan", "--rules", rules, "--no-inline-allow", "--format", "json", "filesystem", target)
	if !IsFindingsError(err) || !strings.Contains(out, `"fingerprint"`) {
		t.Fatalf("--no-inline-allow must report the annotated secret with a fingerprint; err=%v out=%s", err, out)
	}
	out, _, err = runRootCapture(t, "", "scan", "--rules", rules, "--no-inline-allow", "--show-suppressed", "--skip-word", "abcdefgh", "--format", "json", "filesystem", target)
	if err != nil || !strings.Contains(out, `"suppressed_by": "allowlist"`) {
		t.Fatalf("--skip-word must suppress (audited under --show-suppressed); err=%v out=%s", err, out)
	}
	if _, _, err := runRootCapture(t, "", "scan", "--rules", rules, "--no-inline-allow", "--skip-regex", "^FIXTURE_A", "filesystem", target); err != nil {
		t.Fatalf("--skip-regex must suppress; err=%v", err)
	}
	if _, _, err := runRootCapture(t, "", "scan", "--rules", rules, "--skip-regex", "(", "filesystem", target); err == nil {
		t.Fatal("invalid --skip-regex must be rejected")
	}
}

func TestProtectHonorsInlineAllow(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	chdir(t, dir)
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	mustWrite(t, filepath.Join(dir, "a.env"), "token=FIXTURE_ABCDEFGHIJKLMNOPQRST # pleno-dlp:allow\n")
	runGit(t, dir, "add", "a.env")
	rules := filepath.Join(t.TempDir(), "rules.json")
	mustWrite(t, rules, baselineFixtureRules)

	if _, stderr, err := runRootCapture(t, "", "protect", "--rules", rules); err != nil {
		t.Fatalf("inline-allowed staged secret must not block; err=%v stderr=%s", err, stderr)
	}
	if _, _, err := runRootCapture(t, "", "protect", "--rules", rules, "--no-inline-allow"); !IsFindingsError(err) {
		t.Fatalf("--no-inline-allow must block; err=%v", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
