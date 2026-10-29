// Package cmd: `pleno-dlp hooks` installs a fast, offline agent/editor
// hook (issue #303). The hook itself is just this binary re-invoked as
// `pleno-dlp hooks run <target>` — install/uninstall only write a tiny
// wrapper script plus the target's own hook-registration file, and never
// duplicate scanning logic: every hook uses the shared scan pipeline
// in-process with verification disabled.
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"

	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

const (
	hookTargetClaudeCode = "claude-code"
	hookTargetCursor     = "cursor"
	hookTargetGit        = "git"

	// hookScriptMarker is the substring every registered hook command
	// must contain, used to find (and only ever touch) our own entry
	// inside a settings/hooks file that may hold unrelated hooks too.
	hookScriptMarker = "pleno-dlp-scan.sh"
)

var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Install, remove, or run a fast offline agent hook (pre-commit-style) backed by `scan stdin --no-verify`",
	Long: "Manage a latency-tolerant secret-scanning hook for AI coding agents.\n\n" +
		"`pleno-dlp hooks install claude-code|cursor` wires up the target's own hook\n" +
		"mechanism to call `pleno-dlp scan stdin --no-verify` — the network Verify()\n" +
		"round-trip is skipped so the hook stays fast enough to run on every edit or\n" +
		"commit. Findings are still reported (as unverified, never provider-confirmed)\n" +
		"so the hook trades confidence for latency; it is not a substitute for CI's\n" +
		"fully-verified `pleno-dlp scan` gate.\n\n" +
		"`pleno-dlp hooks run <target>` is internal plumbing invoked by the installed\n" +
		"hook config — it is not meant to be run directly.",
}

var hooksInstallCmd = &cobra.Command{
	Use:   "install <claude-code|cursor|git>",
	Short: "Install the hook for claude-code, cursor, or git pre-commit in the current project",
	Args:  cobra.ExactArgs(1),
	RunE:  runHooksInstall,
}

var hooksUninstallCmd = &cobra.Command{
	Use:   "uninstall <claude-code|cursor|git>",
	Short: "Remove a previously installed hook",
	Args:  cobra.ExactArgs(1),
	RunE:  runHooksUninstall,
}

var hooksRunCmd = &cobra.Command{
	Use:    "run <claude-code|cursor|git>",
	Short:  "Internal: translate one hook invocation into a scan stdin --no-verify call",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE:   runHooksRun,
}

var hooksPrintCmd = &cobra.Command{
	Use:   "print <git>",
	Short: "Print a PATH-resolving git pre-commit script for hooks managed outside the repo (core.hooksPath, home-manager, lefthook)",
	Args:  cobra.ExactArgs(1),
	RunE:  runHooksPrint,
}

// hooksFailOn is the --fail-on threshold for the git target. It shares
// scan's vocabulary and parser (parseFailOn) so a hook and a CI scan
// configured with the same word gate on the same severities.
var hooksFailOn string

func init() {
	const failOnUsage = "git target only: minimum severity that blocks the commit: any|info|low|medium|high|critical"
	for _, c := range []*cobra.Command{hooksInstallCmd, hooksRunCmd, hooksPrintCmd} {
		c.Flags().StringVar(&hooksFailOn, "fail-on", "high", failOnUsage)
	}
	hooksCmd.AddCommand(hooksInstallCmd, hooksUninstallCmd, hooksRunCmd, hooksPrintCmd)
	Root.AddCommand(hooksCmd)
}

// hooksUnknownTarget keeps the three switch statements' error text in
// one place so adding a target cannot leave one message stale.
func hooksUnknownTarget(verb, got string) error {
	return fmt.Errorf("hooks %s: unknown target %q (want %q, %q, or %q)", verb, got, hookTargetClaudeCode, hookTargetCursor, hookTargetGit)
}

// rejectFailOnForAgentTargets refuses --fail-on on claude-code/cursor,
// whose hooks block on any finding; silently ignoring the flag would
// let an operator believe they configured a threshold that is not applied.
func rejectFailOnForAgentTargets(cmd *cobra.Command, target string) error {
	if f := cmd.Flags().Lookup("fail-on"); f != nil && f.Changed {
		return fmt.Errorf("hooks %s %s: --fail-on applies only to the %q target", cmd.Name(), target, hookTargetGit)
	}
	return nil
}

func runHooksInstall(cmd *cobra.Command, args []string) error {
	switch args[0] {
	case hookTargetClaudeCode:
		if err := rejectFailOnForAgentTargets(cmd, args[0]); err != nil {
			return err
		}
		return installClaudeCodeHook(cmd)
	case hookTargetCursor:
		if err := rejectFailOnForAgentTargets(cmd, args[0]); err != nil {
			return err
		}
		return installCursorHook(cmd)
	case hookTargetGit:
		return installGitHook(cmd)
	default:
		return hooksUnknownTarget("install", args[0])
	}
}

func runHooksUninstall(cmd *cobra.Command, args []string) error {
	switch args[0] {
	case hookTargetClaudeCode:
		return uninstallClaudeCodeHook(cmd)
	case hookTargetCursor:
		return uninstallCursorHook(cmd)
	case hookTargetGit:
		return uninstallGitHook(cmd)
	default:
		return hooksUnknownTarget("uninstall", args[0])
	}
}

func runHooksRun(cmd *cobra.Command, args []string) error {
	switch args[0] {
	case hookTargetClaudeCode:
		if err := rejectFailOnForAgentTargets(cmd, args[0]); err != nil {
			return err
		}
		return runHookClaudeCode(cmd)
	case hookTargetCursor:
		if err := rejectFailOnForAgentTargets(cmd, args[0]); err != nil {
			return err
		}
		return runHookCursor(cmd)
	case hookTargetGit:
		return runHookGit(cmd)
	default:
		return hooksUnknownTarget("run", args[0])
	}
}

func runHooksPrint(cmd *cobra.Command, args []string) error {
	if args[0] != hookTargetGit {
		return fmt.Errorf("hooks print: unknown target %q (only %q has a standalone script; claude-code and cursor need their settings file, use `hooks install`)", args[0], hookTargetGit)
	}
	script, err := gitHookScriptPortable(hooksFailOn)
	if err != nil {
		return err
	}
	_, err = io.WriteString(cmd.OutOrStdout(), script)
	return err
}

// ---------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------

// hookScriptTemplate is the wrapper every installed hook actually
// executes. Both targets get a real script file (rather than an inline
// "binary + args" command string) because Cursor's hooks.json documents
// script-file entries but is not documented to split an argv the way a
// shell would — a generated script sidesteps that ambiguity for both
// targets uniformly.
const hookScriptTemplate = `#!/bin/sh
# Generated by ` + "`pleno-dlp hooks install %s`" + `. Do not edit by hand —
# re-run that command after upgrading or moving pleno-dlp to refresh the
# embedded binary path below.
exec %s hooks run %s
`

// shellQuote renders s as a POSIX single-quoted token safe to embed in a
// generated shell script. fmt's %q is not safe here: it produces a Go
// double-quoted literal that leaves $, backticks, and ! untouched, so an
// executable path containing shell metacharacters (for example a
// directory named $(id)) would run command substitution on every hook
// invocation. Single quotes admit no expansion, so the only byte that
// needs escaping is ' itself.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeHookScript (re)writes the wrapper script at relPath (relative to
// the current working directory) and returns relPath. Always overwrites:
// the script has no user-editable content, and reinstalling after an
// upgrade should always pick up the current binary path.
func writeHookScript(relPath, target string) (string, error) {
	exe := resolveExecutable()
	if exe == "" {
		return "", fmt.Errorf("hooks install: could not resolve pleno-dlp's own executable path")
	}
	if dir := filepath.Dir(relPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", dir, err)
		}
	}
	script := fmt.Sprintf(hookScriptTemplate, target, shellQuote(exe), target)
	if err := os.WriteFile(relPath, []byte(script), 0o755); err != nil {
		return "", fmt.Errorf("write %s: %w", relPath, err)
	}
	return relPath, nil
}

// removeHookScript deletes the wrapper script, tolerating "already gone".
func removeHookScript(relPath string) error {
	if err := os.Remove(relPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", relPath, err)
	}
	return nil
}

// loadJSONObject reads path as a top-level JSON object, preserving every
// key it doesn't understand as raw bytes so install/uninstall never
// clobbers unrelated settings. A missing or empty file yields an empty
// object rather than an error — first install has nothing to merge into.
func loadJSONObject(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]json.RawMessage{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("parse %s (not a JSON object): %w", path, err)
	}
	return obj, nil
}

func writeJSONObject(path string, obj map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// scanOfflineFunc is the seam runHookClaudeCode / runHookCursor call
// through instead of scanOffline directly. Production leaves it at the
// default; tests replace it with a fake so the allow/deny decision logic
// is verifiable without running the full scan pipeline (mirrors the
// uvBin/gitBin override pattern in pii_server.go).
var scanOfflineFunc = scanOffline

// hookFinding is the subset of one `--format json` record (schema in
// pkg/output/json.go) the hooks consume. Raw is never serialized there,
// so nothing here can carry an unmasked secret except whatever the
// detector chose to put in Redacted — see maskRedacted.
type hookFinding struct {
	Detector     string `json:"detector"`
	Severity     string `json:"severity"`
	Redacted     string `json:"redacted"`
	SuppressedBy string `json:"suppressed_by,omitempty"`
	// Start is the byte offset of the match inside the scanned stdin
	// buffer; the git hook maps it back to a staged path and line.
	Start *int `json:"start,omitempty"`
}

// offlineScanRequest preserves the source location of an edit or staged diff.
type offlineScanRequest struct {
	Data  []byte
	Label string
	Diff  bool
}

// scanOffline uses the shared in-process scan and allowlist pipeline.
func scanOffline(req offlineScanRequest) ([]hookFinding, error) {
	prior := stdinOpts
	defer func() { stdinOpts = prior }()
	stdinOpts.label = req.Label
	stdinOpts.diff = req.Diff
	return scanHookBuffer(&cobra.Command{}, func(sub *cobra.Command) error {
		sub.SetIn(bytes.NewReader(req.Data))
		return runScanStdin(sub, nil)
	})
}

// ---------------------------------------------------------------------
// claude-code: PreToolUse hook on Edit|Write in .claude/settings.json
// ---------------------------------------------------------------------

const (
	claudeScriptPath   = ".claude/hooks/pleno-dlp-scan.sh"
	claudeSettingsPath = ".claude/settings.json"
	claudeHookCommand  = "${CLAUDE_PROJECT_DIR}/" + claudeScriptPath
)

type claudeHookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type claudeMatcher struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []claudeHookEntry `json:"hooks"`
}

func installClaudeCodeHook(cmd *cobra.Command) error {
	if _, err := writeHookScript(claudeScriptPath, hookTargetClaudeCode); err != nil {
		return err
	}

	root, err := loadJSONObject(claudeSettingsPath)
	if err != nil {
		return err
	}
	hooksObj := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooksObj); err != nil {
			return fmt.Errorf("parse %s: key \"hooks\": %w", claudeSettingsPath, err)
		}
	}
	var preToolUse []claudeMatcher
	if raw, ok := hooksObj["PreToolUse"]; ok {
		if err := json.Unmarshal(raw, &preToolUse); err != nil {
			return fmt.Errorf("parse %s: key \"hooks.PreToolUse\": %w", claudeSettingsPath, err)
		}
	}

	state := "installed"
	found := false
	for mi := range preToolUse {
		for hi := range preToolUse[mi].Hooks {
			if !strings.Contains(preToolUse[mi].Hooks[hi].Command, hookScriptMarker) {
				continue
			}
			found = true
			if preToolUse[mi].Hooks[hi].Command != claudeHookCommand {
				preToolUse[mi].Hooks[hi].Command = claudeHookCommand
				state = "updated"
			}
		}
	}
	if !found {
		preToolUse = append(preToolUse, claudeMatcher{
			Matcher: "Edit|Write",
			Hooks:   []claudeHookEntry{{Type: "command", Command: claudeHookCommand}},
		})
	} else if state != "updated" {
		state = "unchanged"
	}

	if state == "unchanged" {
		termsafe.Fprintf(cmd.OutOrStdout(), "claude-code hook already installed in %s (PreToolUse Edit|Write -> %s)\n", claudeSettingsPath, claudeHookCommand)
		return nil
	}

	raw, err := json.Marshal(preToolUse)
	if err != nil {
		return err
	}
	hooksObj["PreToolUse"] = raw
	hooksRaw, err := json.Marshal(hooksObj)
	if err != nil {
		return err
	}
	root["hooks"] = hooksRaw
	if err := writeJSONObject(claudeSettingsPath, root); err != nil {
		return err
	}

	termsafe.Fprintf(cmd.OutOrStdout(), "%s claude-code hook:\n  script:   %s\n  settings: %s\n  trigger:  PreToolUse Edit|Write -> %s\n",
		map[string]string{"installed": "installed", "updated": "updated"}[state], claudeScriptPath, claudeSettingsPath, claudeHookCommand)
	return nil
}

func uninstallClaudeCodeHook(cmd *cobra.Command) error {
	root, err := loadJSONObject(claudeSettingsPath)
	if err != nil {
		return err
	}
	hooksObj := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooksObj); err != nil {
			return fmt.Errorf("parse %s: key \"hooks\": %w", claudeSettingsPath, err)
		}
	}
	var preToolUse []claudeMatcher
	if raw, ok := hooksObj["PreToolUse"]; ok {
		if err := json.Unmarshal(raw, &preToolUse); err != nil {
			return fmt.Errorf("parse %s: key \"hooks.PreToolUse\": %w", claudeSettingsPath, err)
		}
	}

	removed := false
	kept := make([]claudeMatcher, 0, len(preToolUse))
	for _, m := range preToolUse {
		keptHooks := make([]claudeHookEntry, 0, len(m.Hooks))
		for _, h := range m.Hooks {
			if strings.Contains(h.Command, hookScriptMarker) {
				removed = true
				continue
			}
			keptHooks = append(keptHooks, h)
		}
		if len(keptHooks) > 0 {
			m.Hooks = keptHooks
			kept = append(kept, m)
		}
	}

	if !removed {
		termsafe.Fprintf(cmd.OutOrStdout(), "claude-code hook not installed in %s; nothing to do\n", claudeSettingsPath)
		return nil
	}

	if len(kept) > 0 {
		raw, err := json.Marshal(kept)
		if err != nil {
			return err
		}
		hooksObj["PreToolUse"] = raw
	} else {
		delete(hooksObj, "PreToolUse")
	}
	if len(hooksObj) > 0 {
		hooksRaw, err := json.Marshal(hooksObj)
		if err != nil {
			return err
		}
		root["hooks"] = hooksRaw
	} else {
		delete(root, "hooks")
	}
	if err := writeJSONObject(claudeSettingsPath, root); err != nil {
		return err
	}
	if err := removeHookScript(claudeScriptPath); err != nil {
		return err
	}

	termsafe.Fprintf(cmd.OutOrStdout(), "uninstalled claude-code hook: removed PreToolUse entry from %s and deleted %s\n", claudeSettingsPath, claudeScriptPath)
	return nil
}

// claudeHookPayload is the subset of Claude Code's PreToolUse stdin JSON
// this hook needs. The field that carries the content about to be written
// depends on the tool: Write uses tool_input.content (the whole new file),
// Edit uses tool_input.new_string (the replacement text), and MultiEdit
// uses tool_input.edits[].new_string (one replacement per edit). Reading
// only `content` silently let every Edit/MultiEdit through unscanned, so
// scanClaudeContent below concatenates all three.
type claudeHookPayload struct {
	ToolInput struct {
		FilePath  string `json:"file_path"`
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		Edits     []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	} `json:"tool_input"`
}

// scanClaudeContent returns every piece of about-to-be-written text carried
// by a PreToolUse payload, joined by newlines. Write populates Content;
// Edit populates NewString; MultiEdit populates Edits. A tool call may set
// more than one (or none), so all are collected rather than switched on
// tool_name — the hook scans whatever content is present regardless of
// which tool produced it.
func (p claudeHookPayload) scanClaudeContent() string {
	parts := make([]string, 0, 2+len(p.ToolInput.Edits))
	if p.ToolInput.Content != "" {
		parts = append(parts, p.ToolInput.Content)
	}
	if p.ToolInput.NewString != "" {
		parts = append(parts, p.ToolInput.NewString)
	}
	for _, e := range p.ToolInput.Edits {
		if e.NewString != "" {
			parts = append(parts, e.NewString)
		}
	}
	return strings.Join(parts, "\n")
}

// runHookClaudeCode implements the claude-code half of the PreToolUse
// contract: exit 0 (return nil) allows the Edit/Write, a non-nil error
// exits 2 (see main.go) which Claude Code treats as "block", surfacing
// stderr as the reason. Anything that isn't a genuine "secrets found"
// verdict fails open (allows, with a stderr warning) — a parsing or
// spawn failure in our own plumbing should never be able to wedge every
// edit the agent makes.
func runHookClaudeCode(cmd *cobra.Command) error {
	raw, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		termsafe.Fprintf(cmd.ErrOrStderr(), "hooks run claude-code: read hook payload: %v — allowing\n", err)
		return nil
	}
	var payload claudeHookPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		termsafe.Fprintf(cmd.ErrOrStderr(), "hooks run claude-code: parse hook payload: %v — allowing\n", err)
		return nil
	}
	content := payload.scanClaudeContent()
	if strings.TrimSpace(content) == "" {
		return nil
	}

	records, err := scanOfflineFunc(offlineScanRequest{Data: []byte(content), Label: payload.ToolInput.FilePath})
	if err != nil {
		termsafe.Fprintf(cmd.ErrOrStderr(), "hooks run claude-code: %v — allowing\n", err)
		return nil
	}
	n := len(records)
	if n == 0 {
		return nil
	}
	target := payload.ToolInput.FilePath
	if target == "" {
		target = "(unknown file)"
	}
	return fmt.Errorf("pleno-dlp: %d potential secret(s) found in %s (offline, unverified scan) — rerun `pleno-dlp scan stdin` for full verification, or fix the finding before retrying", n, target)
}

// ---------------------------------------------------------------------
// cursor: beforeShellExecution hook gating `git commit` in .cursor/hooks.json
// ---------------------------------------------------------------------
//
// Cursor's afterFileEdit hook (the direct analogue of claude-code's
// PreToolUse Edit|Write) is documented as observation-only — it cannot
// deny or otherwise block the edit. beforeShellExecution is one of the
// three Cursor hook events that can actually return a permission
// decision, so instead this hook intercepts `git commit` invocations and
// scans the staged diff, which is a closer analogue to a pre-commit hook
// than to an edit-time hook anyway.

const (
	cursorScriptPath  = ".cursor/hooks/pleno-dlp-scan.sh"
	cursorHooksPath   = ".cursor/hooks.json"
	cursorHookEvent   = "beforeShellExecution"
	cursorHookCommand = "hooks/pleno-dlp-scan.sh" // relative to cursorHooksPath's directory
)

type cursorHookEntry struct {
	Command string `json:"command"`
}

func installCursorHook(cmd *cobra.Command) error {
	if _, err := writeHookScript(cursorScriptPath, hookTargetCursor); err != nil {
		return err
	}

	root, err := loadJSONObject(cursorHooksPath)
	if err != nil {
		return err
	}
	hooksObj := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooksObj); err != nil {
			return fmt.Errorf("parse %s: key \"hooks\": %w", cursorHooksPath, err)
		}
	}
	var entries []cursorHookEntry
	if raw, ok := hooksObj[cursorHookEvent]; ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return fmt.Errorf("parse %s: key \"hooks.%s\": %w", cursorHooksPath, cursorHookEvent, err)
		}
	}

	state := "installed"
	found := false
	for i := range entries {
		if !strings.Contains(entries[i].Command, hookScriptMarker) {
			continue
		}
		found = true
		if entries[i].Command != cursorHookCommand {
			entries[i].Command = cursorHookCommand
			state = "updated"
		}
	}
	if !found {
		entries = append(entries, cursorHookEntry{Command: cursorHookCommand})
	} else if state != "updated" {
		state = "unchanged"
	}

	if state == "unchanged" {
		termsafe.Fprintf(cmd.OutOrStdout(), "cursor hook already installed in %s (%s -> %s)\n", cursorHooksPath, cursorHookEvent, cursorHookCommand)
		return nil
	}

	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	hooksObj[cursorHookEvent] = raw
	hooksRaw, err := json.Marshal(hooksObj)
	if err != nil {
		return err
	}
	root["hooks"] = hooksRaw
	root["version"] = json.RawMessage("1")
	if err := writeJSONObject(cursorHooksPath, root); err != nil {
		return err
	}

	termsafe.Fprintf(cmd.OutOrStdout(), "%s cursor hook:\n  script: %s\n  config: %s\n  trigger: %s (gates `git commit`) -> %s\n",
		state, cursorScriptPath, cursorHooksPath, cursorHookEvent, cursorHookCommand)
	return nil
}

func uninstallCursorHook(cmd *cobra.Command) error {
	root, err := loadJSONObject(cursorHooksPath)
	if err != nil {
		return err
	}
	hooksObj := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooksObj); err != nil {
			return fmt.Errorf("parse %s: key \"hooks\": %w", cursorHooksPath, err)
		}
	}
	var entries []cursorHookEntry
	if raw, ok := hooksObj[cursorHookEvent]; ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return fmt.Errorf("parse %s: key \"hooks.%s\": %w", cursorHooksPath, cursorHookEvent, err)
		}
	}

	removed := false
	kept := make([]cursorHookEntry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(e.Command, hookScriptMarker) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}

	if !removed {
		termsafe.Fprintf(cmd.OutOrStdout(), "cursor hook not installed in %s; nothing to do\n", cursorHooksPath)
		return nil
	}

	if len(kept) > 0 {
		raw, err := json.Marshal(kept)
		if err != nil {
			return err
		}
		hooksObj[cursorHookEvent] = raw
	} else {
		delete(hooksObj, cursorHookEvent)
	}
	if len(hooksObj) > 0 {
		hooksRaw, err := json.Marshal(hooksObj)
		if err != nil {
			return err
		}
		root["hooks"] = hooksRaw
	} else {
		delete(root, "hooks")
	}
	if err := writeJSONObject(cursorHooksPath, root); err != nil {
		return err
	}
	if err := removeHookScript(cursorScriptPath); err != nil {
		return err
	}

	termsafe.Fprintf(cmd.OutOrStdout(), "uninstalled cursor hook: removed %s entry from %s and deleted %s\n", cursorHookEvent, cursorHooksPath, cursorScriptPath)
	return nil
}

type cursorHookPayload struct {
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
}

type cursorPermissionOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"userMessage,omitempty"`
	AgentMessage string `json:"agentMessage,omitempty"`
}

// gitRe / commitRe together gate which shell commands pay the scan cost.
// Matching "git" and "commit" as separate whole words (rather than one
// anchored `git\s+commit` pattern) deliberately over-matches unusual
// invocations like `git -C repo commit` or `git commit --amend` at the
// cost of also firing on rarer non-commit commands that happen to
// mention both words — for a hook whose job is to gate commits, a false
// extra (fast, offline) scan is a much cheaper mistake than a missed one.
var (
	gitRe    = regexp.MustCompile(`\bgit\b`)
	commitRe = regexp.MustCompile(`\bcommit\b`)
)

// runHookCursor implements the cursor half of the beforeShellExecution
// contract: unlike claude-code, Cursor's permission decision travels as
// JSON on stdout (the `permission` field), not the process exit code, so
// this always exits 0 and prints either an allow or deny decision. Any
// internal failure (bad payload, git not found, scan spawn failure) fails
// open — allow, with a stderr warning — for the same reason as the
// claude-code path: our own plumbing breaking must never block every
// shell command the agent runs.
func runHookCursor(cmd *cobra.Command) error {
	raw, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return allowCursor(cmd, fmt.Sprintf("read hook payload: %v", err))
	}
	var payload cursorHookPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return allowCursor(cmd, fmt.Sprintf("parse hook payload: %v", err))
	}
	if !gitRe.MatchString(payload.Command) || !commitRe.MatchString(payload.Command) {
		return allowCursor(cmd, "")
	}

	diff, err := gitDiffForScan(cmd.Context(), payload.Cwd, true)
	if err != nil {
		return allowCursor(cmd, fmt.Sprintf("collect staged diff: %v", err))
	}
	if _, origins := stagedDiffForScan(diff); len(origins) == 0 {
		return allowCursor(cmd, "")
	}

	records, err := scanOfflineFunc(offlineScanRequest{Data: diff, Label: "git-diff-staged", Diff: true})
	if err != nil {
		return allowCursor(cmd, fmt.Sprintf("scan staged diff: %v", err))
	}
	n := len(records)
	if n == 0 {
		return allowCursor(cmd, "")
	}

	msg := fmt.Sprintf("pleno-dlp found %d potential secret(s) in the staged diff (offline, unverified scan). "+
		"Run `pleno-dlp scan git --repo .` or `pleno-dlp scan stdin` for full verification before committing.", n)
	return writeCursorPermission(cmd, cursorPermissionOutput{Permission: "deny", UserMessage: msg, AgentMessage: msg})
}

func allowCursor(cmd *cobra.Command, warnMsg string) error {
	if warnMsg != "" {
		termsafe.Fprintf(cmd.ErrOrStderr(), "hooks run cursor: %s — allowing\n", warnMsg)
	}
	return writeCursorPermission(cmd, cursorPermissionOutput{Permission: "allow"})
}

func writeCursorPermission(cmd *cobra.Command, out cursorPermissionOutput) error {
	enc, err := json.Marshal(out)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(enc))
	return nil
}

// ---------------------------------------------------------------------
// git: native pre-commit hook (gitleaks `git --staged` replacement)
// ---------------------------------------------------------------------

// gitHookMarker identifies a pre-commit file pleno-dlp wrote. install
// overwrites and uninstall deletes only files carrying it, so an
// operator's own pre-commit hook is never clobbered.
const gitHookMarker = "# pleno-dlp-git-hook"

// gitHookBlockedFmt is the final stderr line on a blocked commit. It names
// both escape hatches so the operator is never stuck at the prompt.
const gitHookBlockedFmt = "pleno-dlp: blocked commit (%d findings at or above %s). Bypass once with git commit --no-verify; allowlist known fixtures in .pleno-allow.json (see docs/recipes/pre-commit.md).\n"

// stagedScanFunc is the seam hook tests use to replace protect's
// in-process scan; production runs scanStagedBuffer.
var stagedScanFunc = scanStagedBuffer

// severityRank maps a JSON severity string back to detectors.Severity by
// inverting Severity.String, so the vocabulary has one source of truth.
func severityRank(s string) detectors.Severity {
	for sev := detectors.SeverityCritical; sev > detectors.SeverityUnknown; sev-- {
		if sev.String() == s {
			return sev
		}
	}
	return detectors.SeverityUnknown
}

// findingsAtOrAbove keeps unsuppressed records whose severity meets the
// threshold produced by parseFailOn. "any" parses to Info, the floor of
// Severity.String's output, so it keeps every record.
func findingsAtOrAbove(records []hookFinding, threshold detectors.Severity) []hookFinding {
	var kept []hookFinding
	for _, r := range records {
		if r.SuppressedBy == "" && severityRank(r.Severity) >= threshold {
			kept = append(kept, r)
		}
	}
	return kept
}

// maskRedacted bounds what the hook prints to six leading characters.
// Redacted is produced per detector and nothing outside the detector
// enforces its shape, so the hook re-masks rather than trusting it.
func maskRedacted(s string) string {
	r := []rune(strings.TrimSuffix(s, "..."))
	if len(r) == 0 {
		return "(redacted)"
	}
	if len(r) > 6 {
		r = r[:6]
	}
	return string(r) + "..."
}

// runHookGit is `protect` plus hook ergonomics: the diff collection,
// transform, and in-process scan are protect's (collectDiffForScan,
// scanStagedBuffer); this layer adds the masked stderr list, the
// blocked-commit message, and fail-open on plumbing errors so a
// pleno-dlp bug can never prevent a commit. Exit 1 (errFindingsFound)
// blocks.
func runHookGit(cmd *cobra.Command) error {
	threshold, err := parseFailOn(hooksFailOn)
	if err != nil {
		return err
	}
	errw := cmd.ErrOrStderr()
	buf, origins, err := collectDiffForScanFunc(cmd.Context(), "", true)
	if err != nil {
		termsafe.Fprintf(errw, "pleno-dlp: hooks run git: %v — allowing commit\n", err)
		return nil
	}
	if len(origins) == 0 {
		return nil
	}
	records, err := stagedScanFunc(cmd, buf, origins)
	if err != nil {
		termsafe.Fprintf(errw, "pleno-dlp: hooks run git: %v — allowing commit\n", err)
		return nil
	}
	blocking := findingsAtOrAbove(records, threshold)
	if len(blocking) == 0 {
		return nil
	}
	level := strings.ToLower(strings.TrimSpace(hooksFailOn))
	fmt.Fprintln(errw, "pleno-dlp: potential secrets in staged changes (offline, unverified scan):")
	for _, r := range blocking {
		where := "(unknown location)"
		if o, ok := originAt(buf, origins, r.Start); ok {
			where = o.path
			if o.line > 0 {
				where = fmt.Sprintf("%s:%d", o.path, o.line)
			}
		}
		termsafe.Fprintf(errw, "  %-8s %-24s %-12s %s\n", r.Severity, r.Detector, maskRedacted(r.Redacted), where)
	}
	termsafe.Fprintf(errw, gitHookBlockedFmt, len(blocking), level)
	return errFindingsFound
}

// gitHooksDir resolves the directory git will run hooks from. `git
// rev-parse --git-path hooks` honours core.hooksPath (local or global)
// and linked worktrees, so install writes where git actually looks.
func gitHooksDir() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("hooks install git: not inside a git repository: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("hooks install git: run git: %w", err)
	}
	return filepath.Abs(strings.TrimSpace(string(out)))
}

// gitHookScriptInstalled pins the absolute binary path, matching the
// claude-code/cursor wrappers, so the hook does not depend on PATH.
func gitHookScriptInstalled(failOn string) (string, error) {
	if _, err := parseFailOn(failOn); err != nil {
		return "", err
	}
	exe := resolveExecutable()
	if exe == "" {
		return "", fmt.Errorf("hooks install: could not resolve pleno-dlp's own executable path")
	}
	script := fmt.Sprintf(hookScriptTemplate, hookTargetGit, shellQuote(exe), hookTargetGit+" --fail-on "+shellQuote(failOn))
	return strings.Replace(script, "#!/bin/sh\n", "#!/bin/sh\n"+gitHookMarker+"\n", 1), nil
}

// gitHookScriptPortable resolves pleno-dlp from PATH for hooks shared
// across machines (dotfiles, core.hooksPath); when the binary is
// missing it warns and lets the commit through rather than failing.
func gitHookScriptPortable(failOn string) (string, error) {
	if _, err := parseFailOn(failOn); err != nil {
		return "", err
	}
	return "#!/bin/sh\n" + gitHookMarker + "\n" +
		"# Generated by `pleno-dlp hooks print git`. Resolves pleno-dlp from PATH.\n" +
		"if ! command -v pleno-dlp >/dev/null 2>&1; then\n" +
		"  echo 'pleno-dlp: not found on PATH; skipping staged secret scan' >&2\n" +
		"  exit 0\n" +
		"fi\n" +
		"exec pleno-dlp hooks run git --fail-on " + shellQuote(failOn) + "\n", nil
}

func installGitHook(cmd *cobra.Command) error {
	script, err := gitHookScriptInstalled(hooksFailOn)
	if err != nil {
		return err
	}
	dir, err := gitHooksDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "pre-commit")
	state := "installed"
	existing, err := os.ReadFile(path)
	switch {
	case err == nil && !strings.Contains(string(existing), gitHookMarker):
		return fmt.Errorf("hooks install git: %s already exists and was not written by pleno-dlp; refusing to overwrite. "+
			"Run `pleno-dlp hooks print git` and merge its last line into your hook by hand", path)
	case err == nil && string(existing) == script:
		termsafe.Fprintf(cmd.OutOrStdout(), "git pre-commit hook already installed at %s\n", path)
		return nil
	case err == nil:
		state = "updated"
	case !os.IsNotExist(err):
		return fmt.Errorf("hooks install git: read %s: %w", path, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hooks install git: create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		return fmt.Errorf("hooks install git: write %s: %w", path, err)
	}
	// WriteFile keeps an existing file's mode; force the exec bit on update.
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("hooks install git: chmod %s: %w", path, err)
	}
	termsafe.Fprintf(cmd.OutOrStdout(), "%s git pre-commit hook:\n  path:    %s\n  fail-on: %s\n", state, path, hooksFailOn)
	return nil
}

func uninstallGitHook(cmd *cobra.Command) error {
	dir, err := gitHooksDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "pre-commit")
	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		termsafe.Fprintf(cmd.OutOrStdout(), "git pre-commit hook not installed at %s; nothing to do\n", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("hooks uninstall git: read %s: %w", path, err)
	}
	if !strings.Contains(string(existing), gitHookMarker) {
		termsafe.Fprintf(cmd.OutOrStdout(), "%s was not written by pleno-dlp; leaving it untouched\n", path)
		return nil
	}
	if err := removeHookScript(path); err != nil {
		return err
	}
	termsafe.Fprintf(cmd.OutOrStdout(), "uninstalled git pre-commit hook: deleted %s\n", path)
	return nil
}
