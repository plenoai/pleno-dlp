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

// scanFlags holds the per-invocation flag values. Bound once at init() and
// read inside RunE — cobra's Flags() introspection works fine but a struct
// keeps the dependency graph between flag and use site explicit.
type scanFlags struct {
	format      string
	verify      bool
	concurrency int
}

var scanOpts scanFlags

// scanCmd is the only subcommand in the MVP. It walks one or more filesystem
// paths, runs every registered detector, and prints findings in the chosen
// format. Exit code is 1 when any finding is emitted so CI can `set -e`.
var scanCmd = &cobra.Command{
	Use:   "scan <path> [path...]",
	Short: "Scan filesystem paths for leaked secrets",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanOpts.format, "format", "table", "output format: json, sarif, table")
	scanCmd.Flags().BoolVar(&scanOpts.verify, "verify", false, "verify candidate secrets against upstream APIs")
	scanCmd.Flags().IntVar(&scanOpts.concurrency, "concurrency", 8, "number of scan workers")
	Root.AddCommand(scanCmd)
}

// runScan is the cobra entrypoint. We intentionally route through helper
// functions that don't touch os.Exit so tests can drive the same code path
// without forking a subprocess.
func runScan(cmd *cobra.Command, args []string) error {
	// SIGINT / SIGTERM cancel the context so the engine drains in-flight
	// chunks instead of leaving worker goroutines blocked on send.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src := sources.New(sources.SourceFilesystem)
	if src == nil {
		return fmt.Errorf("filesystem source is not registered (missing pkg/sources/all import?)")
	}

	cfg, err := json.Marshal(map[string]any{"paths": args})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	if err := src.Init(ctx, "cli", 0, 0, scanOpts.verify, cfg, scanOpts.concurrency); err != nil {
		return fmt.Errorf("init filesystem source: %w", err)
	}

	sink, err := output.NewSink(scanOpts.format, cmd.OutOrStdout())
	if err != nil {
		return err
	}

	// Wrap with the counting+dedup chain. Order matters: dedup is the outer
	// layer so the counter only sees unique findings, which makes the exit
	// code reflect what the user actually saw.
	counter := &countingSink{inner: sink}
	deduped := engine.NewDedup(counter)
	defer func() { _ = sink.Close() }()

	eng := engine.New(engine.Options{
		Verify:      scanOpts.verify,
		Concurrency: scanOpts.concurrency,
	}, deduped)

	if err := eng.Run(ctx, src); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if counter.count.Load() > 0 {
		// Surface non-zero exit without printing to stderr — cobra would
		// double-print the error otherwise. SilenceErrors on Root keeps it
		// quiet, but we still need a sentinel cobra recognises.
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
