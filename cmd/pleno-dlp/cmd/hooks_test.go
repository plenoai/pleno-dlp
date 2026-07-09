package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeScanOffline replaces scanOfflineFunc for the duration of the
// test and restores the real implementation afterward, mirroring the
// uvBin/gitBin override pattern in pii_server.go. fn also lets callers
// assert the hook actually invoked (or skipped) the scan.
func withFakeScanOffline(t *testing.T, fn func(data []byte) (int, error)) {
	t.Helper()
	orig := scanOfflineFunc
	scanOfflineFunc = fn
	t.Cleanup(func() { scanOfflineFunc = orig })
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestHooksInstall_UnknownTargetRejected pins the same "reject unknown
// names loudly" contract filterDetectors already follows for
// --include-detectors: a typo'd target must fail, not silently no-op.
func TestHooksInstall_UnknownTargetRejected(t *testing.T) {
	resetCommandFlags(t)
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "vscode"})
	if err := Root.Execute(); err == nil {
		t.Fatal("expected an error for an unknown hooks target")
	} else if !strings.Contains(err.Error(), "vscode") {
		t.Errorf("error should name the bad target; got %v", err)
	}
}

func TestHooksUninstall_UnknownTargetRejected(t *testing.T) {
	resetCommandFlags(t)
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "uninstall", "vscode"})
	if err := Root.Execute(); err == nil {
		t.Fatal("expected an error for an unknown hooks target")
	}
}

// TestHooksInstallClaudeCode_WritesScriptAndSettings is the happy-path
// contract test: install must write an executable wrapper script and
// register a PreToolUse/Edit|Write entry pointing at it.
func TestHooksInstallClaudeCode_WritesScriptAndSettings(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("install claude-code: %v\n%s", err, out.String())
	}

	scriptInfo, err := os.Stat(filepath.Join(dir, ".claude", "hooks", "pleno-dlp-scan.sh"))
	if err != nil {
		t.Fatalf("hook script not written: %v", err)
	}
	if scriptInfo.Mode()&0o111 == 0 {
		t.Errorf("hook script must be executable, got mode %v", scriptInfo.Mode())
	}

	settings := readJSONFile(t, filepath.Join(dir, ".claude", "settings.json"))
	preToolUse := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("want 1 PreToolUse matcher, got %d: %v", len(preToolUse), preToolUse)
	}
	matcher := preToolUse[0].(map[string]any)
	if matcher["matcher"] != "Edit|Write" {
		t.Errorf("matcher = %v, want Edit|Write", matcher["matcher"])
	}
	hooks := matcher["hooks"].([]any)[0].(map[string]any)
	if !strings.Contains(hooks["command"].(string), "pleno-dlp-scan.sh") {
		t.Errorf("command %v does not reference the hook script", hooks["command"])
	}
}

// TestHooksInstallClaudeCode_PreservesExistingSettings guards against
// the failure mode this whole JSON-merge approach exists to avoid:
// clobbering unrelated settings.json content (other top-level keys,
// and other hook events) that the user already configured.
func TestHooksInstallClaudeCode_PreservesExistingSettings(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{
		"env": {"FOO": "bar"},
		"hooks": {
			"Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("install claude-code: %v\n%s", err, out.String())
	}

	settings := readJSONFile(t, filepath.Join(dir, ".claude", "settings.json"))
	if settings["env"].(map[string]any)["FOO"] != "bar" {
		t.Errorf("unrelated top-level key \"env\" was not preserved: %v", settings["env"])
	}
	hooksObj := settings["hooks"].(map[string]any)
	if _, ok := hooksObj["Stop"]; !ok {
		t.Errorf("unrelated hook event \"Stop\" was not preserved: %v", hooksObj)
	}
	if _, ok := hooksObj["PreToolUse"]; !ok {
		t.Errorf("PreToolUse was not added: %v", hooksObj)
	}
}

// TestHooksInstallClaudeCode_Idempotent asserts a second install neither
// duplicates the PreToolUse entry nor rewrites settings.json.
func TestHooksInstallClaudeCode_Idempotent(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	Root.SetOut(&bytes.Buffer{})
	Root.SetErr(&bytes.Buffer{})
	Root.SetArgs([]string{"hooks", "install", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first install: %v", err)
	}
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	resetCommandFlagsNow()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already installed") {
		t.Errorf("expected an \"already installed\" message; got:\n%s", out.String())
	}

	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("settings.json changed on a no-op reinstall:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	settings := readJSONFile(t, settingsPath)
	preToolUse := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("reinstall must not duplicate the matcher entry, got %d", len(preToolUse))
	}
}

// TestHooksUninstallClaudeCode_RemovesEntryPreservesOthers checks
// uninstall deletes only our own PreToolUse entry (and the wrapper
// script) while leaving unrelated hooks and settings alone.
func TestHooksUninstallClaudeCode_RemovesEntryPreservesOthers(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	Root.SetOut(&bytes.Buffer{})
	Root.SetErr(&bytes.Buffer{})
	Root.SetArgs([]string{"hooks", "install", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	settings := readJSONFile(t, settingsPath)
	settings["hooks"].(map[string]any)["Stop"] = []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "echo done"}}}}
	rewriteJSONFile(t, settingsPath, settings)

	resetCommandFlagsNow()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "uninstall", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}

	if _, err := os.Stat(filepath.Join(dir, ".claude", "hooks", "pleno-dlp-scan.sh")); !os.IsNotExist(err) {
		t.Errorf("hook script should have been removed, stat err = %v", err)
	}
	after := readJSONFile(t, settingsPath)
	hooksObj := after["hooks"].(map[string]any)
	if _, ok := hooksObj["PreToolUse"]; ok {
		t.Errorf("PreToolUse should have been removed: %v", hooksObj)
	}
	if _, ok := hooksObj["Stop"]; !ok {
		t.Errorf("unrelated Stop hook should have been preserved: %v", hooksObj)
	}

	resetCommandFlagsNow()
	var out2 bytes.Buffer
	Root.SetOut(&out2)
	Root.SetErr(&out2)
	Root.SetArgs([]string{"hooks", "uninstall", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
	if !strings.Contains(out2.String(), "not installed") {
		t.Errorf("second uninstall should say there's nothing to do; got:\n%s", out2.String())
	}
}

// TestHooksInstallCursor_WritesScriptAndConfig mirrors the claude-code
// happy-path test for cursor's flatter hooks.json shape.
func TestHooksInstallCursor_WritesScriptAndConfig(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("install cursor: %v\n%s", err, out.String())
	}

	if _, err := os.Stat(filepath.Join(dir, ".cursor", "hooks", "pleno-dlp-scan.sh")); err != nil {
		t.Fatalf("hook script not written: %v", err)
	}
	settings := readJSONFile(t, filepath.Join(dir, ".cursor", "hooks.json"))
	if settings["version"].(float64) != 1 {
		t.Errorf("version = %v, want 1", settings["version"])
	}
	entries := settings["hooks"].(map[string]any)["beforeShellExecution"].([]any)
	if len(entries) != 1 {
		t.Fatalf("want 1 beforeShellExecution entry, got %d", len(entries))
	}
	cmdField := entries[0].(map[string]any)["command"].(string)
	if !strings.Contains(cmdField, "pleno-dlp-scan.sh") {
		t.Errorf("command %v does not reference the hook script", cmdField)
	}
}

func TestHooksInstallCursor_Idempotent(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	Root.SetOut(&bytes.Buffer{})
	Root.SetErr(&bytes.Buffer{})
	Root.SetArgs([]string{"hooks", "install", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first install: %v", err)
	}

	resetCommandFlagsNow()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "install", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already installed") {
		t.Errorf("expected an \"already installed\" message; got:\n%s", out.String())
	}

	settings := readJSONFile(t, filepath.Join(dir, ".cursor", "hooks.json"))
	entries := settings["hooks"].(map[string]any)["beforeShellExecution"].([]any)
	if len(entries) != 1 {
		t.Fatalf("reinstall must not duplicate the entry, got %d", len(entries))
	}
}

func TestHooksUninstallCursor_RemovesEntry(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)

	Root.SetOut(&bytes.Buffer{})
	Root.SetErr(&bytes.Buffer{})
	Root.SetArgs([]string{"hooks", "install", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	resetCommandFlagsNow()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"hooks", "uninstall", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}

	if _, err := os.Stat(filepath.Join(dir, ".cursor", "hooks", "pleno-dlp-scan.sh")); !os.IsNotExist(err) {
		t.Errorf("hook script should have been removed, stat err = %v", err)
	}
	settings := readJSONFile(t, filepath.Join(dir, ".cursor", "hooks.json"))
	hooksObj, ok := settings["hooks"].(map[string]any)
	if ok {
		if _, ok := hooksObj["beforeShellExecution"]; ok {
			t.Errorf("beforeShellExecution should have been removed: %v", hooksObj)
		}
	}
}

// --- runHookClaudeCode / runHookCursor decision-logic tests ---
// These inject a fake scanOfflineFunc so the allow/deny/fail-open
// branching is verified directly, without spawning a real subprocess.
// The real scanOffline -> `pleno-dlp scan stdin --no-verify` wiring is
// covered end-to-end by TestScanStdin_NoVerifySkipsNetworkCall in
// scan_test.go and by manual verification with a built binary.

func TestRunHookClaudeCode_AllowsCleanContent(t *testing.T) {
	resetCommandFlags(t)
	withFakeScanOffline(t, func(data []byte) (int, error) { return 0, nil })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"foo.txt","content":"hello world"}}`))
	Root.SetArgs([]string{"hooks", "run", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("expected clean content to be allowed, got error: %v\n%s", err, out.String())
	}
}

func TestRunHookClaudeCode_BlocksOnFindings(t *testing.T) {
	resetCommandFlags(t)
	var gotData string
	withFakeScanOffline(t, func(data []byte) (int, error) {
		gotData = string(data)
		return 2, nil
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"secrets.env","content":"AWS_KEY=AKIA..."}}`))
	Root.SetArgs([]string{"hooks", "run", "claude-code"})
	err := Root.Execute()
	if err == nil {
		t.Fatal("expected an error (block) when scanOfflineFunc reports findings")
	}
	if !strings.Contains(err.Error(), "secrets.env") {
		t.Errorf("error should name the file; got %v", err)
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error should mention the finding count; got %v", err)
	}
	if gotData != "AWS_KEY=AKIA..." {
		t.Errorf("scanOfflineFunc got %q, want the tool_input.content verbatim", gotData)
	}
}

func TestRunHookClaudeCode_FailsOpenOnScanError(t *testing.T) {
	resetCommandFlags(t)
	withFakeScanOffline(t, func(data []byte) (int, error) {
		return 0, os.ErrPermission // simulate a spawn / infra failure
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"foo.txt","content":"anything"}}`))
	Root.SetArgs([]string{"hooks", "run", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("infra failure must fail open (allow), got error: %v", err)
	}
	if !strings.Contains(out.String(), "allowing") {
		t.Errorf("expected a fail-open warning on stderr; got:\n%s", out.String())
	}
}

func TestRunHookClaudeCode_AllowsMalformedPayload(t *testing.T) {
	resetCommandFlags(t)
	calls := 0
	withFakeScanOffline(t, func(data []byte) (int, error) {
		calls++
		return 0, nil
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader(`not json`))
	Root.SetArgs([]string{"hooks", "run", "claude-code"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("malformed payload must fail open, got error: %v", err)
	}
	if calls != 0 {
		t.Errorf("scan must not run against an unparseable payload, got %d calls", calls)
	}
}

func TestRunHookCursor_AllowsNonCommitCommandWithoutScanning(t *testing.T) {
	resetCommandFlags(t)
	calls := 0
	withFakeScanOffline(t, func(data []byte) (int, error) {
		calls++
		return 5, nil // if this ever ran, it would deny — proves the skip below matters
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader(`{"command":"ls -la","cwd":"/tmp"}`))
	Root.SetArgs([]string{"hooks", "run", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("cursor hook run should not itself error: %v", err)
	}
	if calls != 0 {
		t.Errorf("a non-commit command must never pay the scan cost, got %d scan calls", calls)
	}
	var decision map[string]any
	if err := json.Unmarshal(out.Bytes(), &decision); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if decision["permission"] != "allow" {
		t.Errorf("permission = %v, want allow", decision["permission"])
	}
}

func TestRunHookCursor_DeniesOnFindingsInStagedDiff(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "leak.env"), []byte("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "leak.env")

	withFakeScanOffline(t, func(data []byte) (int, error) {
		if !strings.Contains(string(data), "AKIA1234567890ABCDEF") {
			t.Errorf("scanOfflineFunc should receive the staged diff; got %q", data)
		}
		return 1, nil
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	payload, err := json.Marshal(map[string]string{"command": "git commit -m wip", "cwd": dir})
	if err != nil {
		t.Fatal(err)
	}
	Root.SetIn(bytes.NewReader(payload))
	Root.SetArgs([]string{"hooks", "run", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("cursor hook run should not itself error: %v", err)
	}

	var decision map[string]any
	if err := json.Unmarshal(out.Bytes(), &decision); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if decision["permission"] != "deny" {
		t.Errorf("permission = %v, want deny", decision["permission"])
	}
	if !strings.Contains(decision["userMessage"].(string), "1 potential secret") {
		t.Errorf("userMessage should mention the finding count: %v", decision["userMessage"])
	}
}

func TestRunHookCursor_AllowsCleanStagedDiff(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing interesting\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "clean.txt")

	withFakeScanOffline(t, func(data []byte) (int, error) { return 0, nil })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	payload, err := json.Marshal(map[string]string{"command": "git commit -m wip", "cwd": dir})
	if err != nil {
		t.Fatal(err)
	}
	Root.SetIn(bytes.NewReader(payload))
	Root.SetArgs([]string{"hooks", "run", "cursor"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("cursor hook run should not itself error: %v", err)
	}
	var decision map[string]any
	if err := json.Unmarshal(out.Bytes(), &decision); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if decision["permission"] != "allow" {
		t.Errorf("permission = %v, want allow", decision["permission"])
	}
}

// readJSONFile / rewriteJSONFile are tiny test helpers for asserting on
// / mutating JSON config files as generic maps.
func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	return m
}

func rewriteJSONFile(t *testing.T, path string, m map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
