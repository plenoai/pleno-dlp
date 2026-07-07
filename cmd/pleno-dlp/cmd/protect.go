package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// protectFlags captures protect-specific options. Scan-wide flags
// (format, verify, fail-on, …) are bound to scanOpts directly so
// operators get the same knobs they already know from `scan`.
type protectFlags struct {
	// staged selects git diff --cached (true) vs git diff (false).
	staged bool
	// noStaged is the explicit --no-staged flag. cobra does not auto-generate
	// negations for BoolVar defaults, so we register it manually and merge
	// it into staged in runProtect.
	noStaged bool
	// repo overrides the git repository root; empty means use cwd.
	// Useful when invoked from outside the repository (e.g. wrapper scripts).
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
	protectCmd.Flags().StringVar(&scanOpts.failOn, "fail-on", "high", "minimum severity that triggers exit 1: any|info|low|medium|high|critical (default high: audit-first — see `scan --help`)")
	protectCmd.Flags().StringVar(&scanOpts.allowlistPath, "allowlist", "", "path to a JSON allowlist file (.pleno-allow.json auto-discovered when unset)")
	protectCmd.Flags().StringSliceVar(&scanOpts.includeDetectors, "include-detectors", nil, "only run these detectors (comma-separated; see `pleno-dlp detectors list`)")
	protectCmd.Flags().StringSliceVar(&scanOpts.excludeDetectors, "exclude-detectors", nil, "skip these detectors (comma-separated)")
	protectCmd.Flags().BoolVar(&scanOpts.quiet, "quiet", false, "suppress the end-of-scan summary line on stderr")

	Root.AddCommand(protectCmd)
}

func runProtect(cmd *cobra.Command, _ []string) error {
	// --no-staged wins over the default --staged=true.
	if protectOpts.noStaged {
		protectOpts.staged = false
	}

	repoDir := protectOpts.repo
	if repoDir == "" {
		var err error
		repoDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("protect: cannot determine cwd: %w", err)
		}
	}

	var gitArgs []string
	var label string
	if protectOpts.staged {
		gitArgs = []string{"diff", "--cached"}
		label = "git-diff-staged"
	} else {
		gitArgs = []string{"diff"}
		label = "git-diff-unstaged"
	}

	diffContent, err := runGitDiff(cmd, repoDir, gitArgs)
	if err != nil {
		return err
	}

	added := extractAddedLines(diffContent)
	if added == "" {
		if !scanOpts.quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "protect: no changes to scan\n")
		}
		return nil
	}

	src := sources.New(sources.SourceStdin)
	if src == nil {
		return fmt.Errorf("stdin source is not registered (missing pkg/sources/all import?)")
	}
	if setter, ok := src.(interface{ SetReader(io.Reader) }); ok {
		setter.SetReader(strings.NewReader(added))
	}

	cfg, err := json.Marshal(map[string]any{
		"label": label,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}

	return runScanCommon(cmd, src, cfg, "protect")
}

// runGitDiff executes `git <args>` in repoDir and returns the combined
// stdout. stderr is forwarded to cmd's stderr so git authentication
// errors are visible to the operator.
func runGitDiff(cmd *cobra.Command, repoDir string, args []string) (string, error) {
	gitCmd := exec.CommandContext(cmd.Context(), "git", args...)
	gitCmd.Dir = repoDir
	gitCmd.Stderr = cmd.ErrOrStderr()
	out, err := gitCmd.Output()
	if err != nil {
		return "", fmt.Errorf("protect: git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// extractAddedLines returns only the added lines from a unified diff,
// stripping the leading '+' so detectors see raw content.
// Removed ('-') and context lines are discarded to avoid false positives
// on secrets that are being deleted.
func extractAddedLines(diff string) string {
	var sb strings.Builder
	for _, line := range strings.SplitAfter(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			sb.WriteString(line[1:]) // strip leading '+'
		}
	}
	return sb.String()
}
