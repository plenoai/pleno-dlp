// Package cmd hosts cobra subcommands for the pleno-dlp binary.
// Each subcommand registers itself with Root from a package-level init(),
// so adding a command means adding one file here — not editing main.go.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/custom"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/output"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Root is the top-level cobra command. main.go calls Root.Execute(); every
// subcommand attaches itself here from its own init(). Exposed as a package
// variable so tests can introspect the wired-up command tree without
// triggering os.Exit.
var Root = &cobra.Command{
	Use:           "pleno-dlp",
	Short:         "Scan sources for leaked secrets",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// SetVersion lets main.go inject build-time version/commit metadata after
// linker flags resolve. Keeping it out of init() ordering avoids races with
// subcommand registration.
func SetVersion(version, commit string) {
	Root.Version = fmt.Sprintf("%s (%s)", version, commit)
}

// scanFlags holds flags that apply across every source kind. Per-source
// flags (paths, repo, since, ...) live on the corresponding subcommand to
// keep cobra's --help output narrow and to give each kind its own validation.
type scanFlags struct {
	format      string
	verify      bool
	concurrency int
	rulesPath   string
}

var scanOpts scanFlags

// scanCmd is the parent command for source-specific subcommands. We keep
// it routable on its own (no positional args required) so that `scan
// --help` still describes the shared flags. The first positional arg
// selects the source kind: `scan filesystem <paths>` or `scan git --repo`.
var scanCmd = &cobra.Command{
	Use:   "scan <kind> [args...]",
	Short: "Scan a source for leaked secrets",
	Long: "Scan a source for leaked secrets. Supported kinds:\n" +
		"  filesystem  walk one or more local paths\n" +
		"  git         walk the commit history of a local git repo",
}

// scanFilesystemCmd preserves the original `scan <path>...` semantics under
// the new `scan filesystem <path>...` form. Keeping it as an explicit
// subcommand removes the implicit-default ambiguity.
var scanFilesystemCmd = &cobra.Command{
	Use:   "filesystem <path> [path...]",
	Short: "Scan local filesystem paths",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScanFilesystem,
}

// gitFlags captures git-specific configuration. Defined alongside scanCmd
// because git is a first-class source for the v1 scope.
type gitFlags struct {
	repo     string
	branch   string
	since    string
	maxDepth int
	include  []string
	exclude  []string
}

var gitOpts gitFlags

// scanGitCmd walks a local git repository's history. Remote URLs are not
// accepted yet — pair this with a separate `clone` step if you need that.
var scanGitCmd = &cobra.Command{
	Use:   "git --repo <path>",
	Short: "Scan a local git repository's commit history",
	Args:  cobra.NoArgs,
	RunE:  runScanGit,
}

func init() {
	// Persistent flags on scanCmd so every subcommand inherits them — keeps
	// `scan filesystem --format json` and `scan git --format json` consistent.
	scanCmd.PersistentFlags().StringVar(&scanOpts.format, "format", "table", "output format: json, sarif, table")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.verify, "verify", false, "verify candidate secrets against upstream APIs")
	scanCmd.PersistentFlags().IntVar(&scanOpts.concurrency, "concurrency", 8, "number of scan workers")
	scanCmd.PersistentFlags().StringVar(&scanOpts.rulesPath, "rules", "", "path to a custom rules JSON file (org-specific patterns)")

	scanGitCmd.Flags().StringVar(&gitOpts.repo, "repo", "", "absolute or relative path to a local git repository")
	scanGitCmd.Flags().StringVar(&gitOpts.branch, "branch", "", "branch to walk (default: HEAD)")
	scanGitCmd.Flags().StringVar(&gitOpts.since, "since", "", "RFC3339 cutoff; commits older than this are skipped")
	scanGitCmd.Flags().IntVar(&gitOpts.maxDepth, "max-depth", 0, "cap on commits walked (0 = unbounded)")
	scanGitCmd.Flags().StringSliceVar(&gitOpts.include, "include", nil, "glob(s) to include (matched against repo-relative paths)")
	scanGitCmd.Flags().StringSliceVar(&gitOpts.exclude, "exclude", nil, "glob(s) to exclude")
	_ = scanGitCmd.MarkFlagRequired("repo")

	scanCmd.AddCommand(scanFilesystemCmd)
	scanCmd.AddCommand(scanGitCmd)
	Root.AddCommand(scanCmd)
}

func runScanFilesystem(cmd *cobra.Command, args []string) error {
	src := sources.New(sources.SourceFilesystem)
	if src == nil {
		return fmt.Errorf("filesystem source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{"paths": args})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "filesystem")
}

func runScanGit(cmd *cobra.Command, _ []string) error {
	src := sources.New(sources.SourceGit)
	if src == nil {
		return fmt.Errorf("git source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"repo":      gitOpts.repo,
		"branch":    gitOpts.branch,
		"since":     gitOpts.since,
		"max_depth": gitOpts.maxDepth,
		"include":   gitOpts.include,
		"exclude":   gitOpts.exclude,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "git")
}

// runScanCommon centralises the source-init -> engine.Run -> sink wiring so
// the per-kind RunE functions only have to translate flags into a JSON config.
func runScanCommon(cmd *cobra.Command, src sources.Source, cfg []byte, kind string) error {
	// SIGINT / SIGTERM cancel the context so the engine drains in-flight
	// chunks instead of leaving worker goroutines blocked on send.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := src.Init(ctx, "cli", 0, 0, scanOpts.verify, cfg, scanOpts.concurrency); err != nil {
		return fmt.Errorf("init %s source: %w", kind, err)
	}

	sink, err := output.NewSink(scanOpts.format, cmd.OutOrStdout())
	if err != nil {
		return err
	}

	dets := detectors.All()
	if scanOpts.rulesPath != "" {
		extra, err := custom.LoadFile(scanOpts.rulesPath)
		if err != nil {
			return err
		}
		for _, d := range extra {
			dets = append(dets, d)
		}
	}

	// Wrap with the counting+dedup chain. Order matters: dedup is the outer
	// layer so the counter only sees unique findings, which makes the exit
	// code reflect what the user actually saw.
	counter := &countingSink{inner: sink}
	deduped := engine.NewDedup(counter)
	defer func() { _ = sink.Close() }()

	eng := engine.NewWithDetectors(dets, engine.Options{
		Verify:      scanOpts.verify,
		Concurrency: scanOpts.concurrency,
	}, deduped)

	if err := eng.Run(ctx, src); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if counter.count.Load() > 0 {
		return errFindingsFound
	}
	return nil
}

// errFindingsFound is the sentinel used to signal "scan succeeded but
// secrets were found". main.go maps this to exit code 1.
var errFindingsFound = fmt.Errorf("findings detected")

// IsFindingsError reports whether err is the findings sentinel. main.go
// uses this to choose its exit code without importing the variable directly.
func IsFindingsError(err error) bool { return err == errFindingsFound }

// countingSink is a tiny pass-through that tallies forwarded findings.
// Lives here rather than pkg/engine because the count is a CLI concern —
// the engine itself has no opinion on exit codes.
type countingSink struct {
	inner engine.Sink
	count atomic.Int64
}

func (c *countingSink) Emit(f engine.Finding) {
	c.count.Add(1)
	c.inner.Emit(f)
}

func (c *countingSink) Close() error { return c.inner.Close() }

// Execute is a thin wrapper main.go invokes. Returning instead of calling
// os.Exit here keeps the cmd package testable.
func Execute(ctx context.Context) error {
	return Root.ExecuteContext(ctx)
}
