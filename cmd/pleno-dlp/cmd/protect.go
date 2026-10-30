package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/stdin"
)

// protectFlags captures protect-specific options. Scan-wide flags
// are bound to scanOpts directly so operators get the same knobs
// they already know from `scan`.
type protectFlags struct {
	// staged selects git diff --cached (true) vs git diff (false).
	staged bool
	// noStaged is the explicit --no-staged flag. cobra does not auto-generate
	// negations for BoolVar defaults, so we register it manually and merge
	// it into staged in runProtect.
	noStaged bool
	// repo overrides the git repository root; empty means use cwd.
	// Useful when invoked from outside the repository.
	repo string
}

var protectOpts protectFlags

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Scan staged git changes for secrets (pre-commit hook)",
	Long: `Runs git diff --cached and scans only the added lines, eliminating
false positives from removed lines that the naive pipe approach produces.

Install as a pre-commit hook:
  echo 'pleno-dlp protect' >> .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit

Pass --no-staged to scan unstaged changes in tracked files (git diff):
  pleno-dlp protect --no-staged
Note: untracked (new) files are not scanned until staged.`,
	Args: cobra.NoArgs,
	RunE: runProtect,
}

func init() {
	protectCmd.Flags().BoolVar(&protectOpts.staged, "staged", true,
		"scan staged changes (git diff --cached)")
	protectCmd.Flags().BoolVar(&protectOpts.noStaged, "no-staged", false,
		"scan working-tree diff (git diff) instead of staged changes; pre-push use")
	protectCmd.Flags().StringVar(&protectOpts.repo, "repo", "",
		"path to the git repository root (default: cwd)")

	// Mirror the scan-wide flags onto protectCmd (same scanOpts as scan.go).
	protectCmd.Flags().StringVar(&scanOpts.format, "format", "table", "output format: json, sarif, table")
	protectCmd.Flags().IntVar(&scanOpts.verifyRPS, "verify-rps", 10, "per-host requests-per-second cap during verification (0 = disable)")
	protectCmd.Flags().IntVar(&scanOpts.concurrency, "concurrency", 8, "number of scan workers")
	protectCmd.Flags().StringVar(&scanOpts.rulesPath, "rules", "", "path to a custom rules JSON file (org-specific patterns)")
	protectCmd.Flags().StringVar(&scanOpts.failOn, "fail-on", "high", "minimum severity that triggers exit 1: any|info|low|medium|high|critical (default high: audit-first — see 'scan --help')")
	protectCmd.Flags().StringVar(&scanOpts.allowlistPath, "allowlist", "", "path to a JSON allowlist file (.pleno-allow.json auto-discovered when unset)")
	protectCmd.Flags().StringSliceVar(&scanOpts.includeDetectors, "include-detectors", nil, "only run these detectors (comma-separated; see 'pleno-dlp detectors list')")
	protectCmd.Flags().StringSliceVar(&scanOpts.excludeDetectors, "exclude-detectors", nil, "skip these detectors (comma-separated)")
	protectCmd.Flags().BoolVar(&scanOpts.quiet, "quiet", false, "suppress the end-of-scan summary line on stderr")

	Root.AddCommand(protectCmd)
}

func runProtect(cmd *cobra.Command, _ []string) error {
	// --no-staged wins over the default --staged=true.
	if protectOpts.noStaged {
		protectOpts.staged = false
	}
	buf, origins, err := collectDiffForScan(cmd.Context(), protectOpts.repo, protectOpts.staged)
	if err != nil {
		return fmt.Errorf("protect: %w", err)
	}
	if len(origins) == 0 {
		if !scanOpts.quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "protect: no changes to scan\n")
		}
		return nil
	}
	return runProtectScan(cmd, buf, origins, protectOpts.staged)
}

// runProtectScan scans a collectDiffForScan buffer through the stdin
// source and the shared scan pipeline under kind "protect", so
// --fail-on, the allowlist, and detector filters gate exactly as for
// any other gated scan kind. Output goes to cmd's writers in
// scanOpts.format.
func runProtectScan(cmd *cobra.Command, buf []byte, origins []diffOrigin, staged bool) error {
	label := "git-diff-unstaged"
	if staged {
		label = "git-diff-staged"
	}
	src := sources.New(sources.SourceStdin)
	if src == nil {
		return fmt.Errorf("stdin source is not registered (missing pkg/sources/all import?)")
	}
	if setter, ok := src.(interface{ SetReader(io.Reader) }); ok {
		setter.SetReader(bytes.NewReader(buf))
	}
	cfg, err := json.Marshal(map[string]any{
		"label":     label,
		"locations": originLocations(origins),
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "protect")
}

// scanStagedBuffer captures the git hook's offline scan in-process.
func scanStagedBuffer(cmd *cobra.Command, buf []byte, origins []diffOrigin) ([]hookFinding, error) {
	return scanHookBuffer(cmd, func(sub *cobra.Command) error {
		return runProtectScan(sub, buf, origins, true)
	})
}

// scanHookBuffer captures the shared scan pipeline's JSON records for hooks
// that render findings and gate severity themselves. Findings errors are
// expected; operational errors still propagate to the hook's fail-open logic.
// CLI options are process-global, so restore them after the synchronous scan.
func scanHookBuffer(cmd *cobra.Command, scan func(*cobra.Command) error) ([]hookFinding, error) {
	prior := scanOpts
	defer func() { scanOpts = prior }()
	var out bytes.Buffer
	sub := &cobra.Command{}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	sub.SetContext(ctx)
	sub.SetOut(&out)
	sub.SetErr(cmd.ErrOrStderr())
	scanOpts.format = "json"
	scanOpts.quiet = true
	scanOpts.noVerify = true
	scanOpts.onlyVerified = false
	scanOpts.failOn = "any"
	if err := scan(sub); err != nil && !IsFindingsError(err) {
		return nil, err
	}
	if len(bytes.TrimSpace(out.Bytes())) == 0 {
		return nil, nil
	}
	var records []hookFinding
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		return nil, fmt.Errorf("parse hook scan output: %w", err)
	}
	return records, nil
}

// extractAddedLines returns only the added lines from a unified diff,
// stripping the leading '+' so detectors see raw content.
// Removed ('-') and context lines are discarded to avoid false positives
// on secrets that are being deleted.
//
// Added lines are recognized by hunk state rather than by prefix alone.
// The '+++ b/file' header appears before the first '@@' marker and is
// skipped, while content added inside a hunk may itself begin with '++'
// (rendered as '+++...') and must still be scanned.
func extractAddedLines(diff string) string {
	var sb strings.Builder
	inHunk := false
	for _, line := range strings.SplitAfter(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff "):
			// Start of a new file's diff section: back to header state
			// so a following '+++ b/file' header is not mistaken for content.
			inHunk = false
		case strings.HasPrefix(line, "@@"):
			inHunk = true
		case inHunk && strings.HasPrefix(line, "+"):
			// Added content line. Lines such as '\ No newline at end of
			// file' start with '\' and are intentionally skipped.
			sb.WriteString(line[1:])
		}
	}
	return sb.String()
}

// collectDiffForScanFunc is the seam hook tests use to inject a diff.
var collectDiffForScanFunc = collectDiffForScan

// collectDiffForScan runs git diff (index vs HEAD when staged, else
// work tree vs index) in repoDir ("" = process cwd, which git sets to
// the work tree root for hooks; GIT_DIR / GIT_INDEX_FILE are inherited)
// and returns stagedDiffForScan's buffer and origins.
// --no-ext-diff / --no-color keep user config from altering the format
// the transform parses; ACMR drops pure deletions, which add no content.
func collectDiffForScan(ctx context.Context, repoDir string, staged bool) ([]byte, []diffOrigin, error) {
	diff, err := gitDiffForScan(ctx, repoDir, staged)
	if err != nil {
		return nil, nil, err
	}
	buf, origins := stagedDiffForScan(diff)
	return buf, origins, nil
}

// gitDiffForScan returns the raw unified diff collectDiffForScan reduces;
// the cursor hook hands it to `scan stdin --diff` unreduced.
func gitDiffForScan(ctx context.Context, repoDir string, staged bool) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	args := []string{"diff", "--diff-filter=ACMR", "--no-color", "--no-ext-diff"}
	if staged {
		args = append(args, "--cached")
	}
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = repoDir
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// diffOrigin attributes one line of the scan buffer to the file and
// new-side line number it came from. line is 0 for a "+++" header.
type diffOrigin struct {
	path string
	line int
}

// stagedDiffForScan reduces a unified diff to the text a change adds
// (see stdin.ParseDiff for the exact transform). The returned origins
// are indexed by buffer line so a finding's byte offset maps back to
// path:line (see originAt).
func stagedDiffForScan(diff []byte) ([]byte, []diffOrigin) {
	buf, locs := stdin.ParseDiff(diff)
	if locs == nil {
		return nil, nil
	}
	origins := make([]diffOrigin, len(locs))
	for i, l := range locs {
		origins[i] = diffOrigin{path: l.Path, line: l.Line}
	}
	return buf, origins
}

// originLocations converts origins into the 1-based buffer-line map the
// stdin source attaches as StdinMeta.Locations, so the engine resolves
// each finding to its real file and allowlist path entries match.
func originLocations(origins []diffOrigin) map[int]sources.LineLocation {
	locs := make([]sources.LineLocation, len(origins))
	for i, o := range origins {
		locs[i] = sources.LineLocation{Path: o.path, Line: o.line}
	}
	return stdin.LocationMap(locs)
}

// originAt maps a byte offset in the stagedDiffForScan buffer to its
// origin; ok is false when the offset is absent or out of range.
func originAt(buf []byte, origins []diffOrigin, start *int) (diffOrigin, bool) {
	if start == nil || *start < 0 || *start > len(buf) {
		return diffOrigin{}, false
	}
	idx := bytes.Count(buf[:*start], []byte{'\n'})
	if idx >= len(origins) {
		return diffOrigin{}, false
	}
	return origins[idx], true
}
