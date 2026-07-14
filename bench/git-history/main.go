package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/plenoai/pleno-dlp/bench/git-history/fixture"
)

type options struct {
	commits        int
	files          int
	window         int
	warmups        int
	runs           int
	minSample      time.Duration
	commandTimeout time.Duration
	enforce        bool
	plenoBin       string
	trufflehogBin  string
	jsonOut        string
	markdownOut    string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "git-history-bench:", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := parseOptions()
	if err != nil {
		return err
	}
	ctx := context.Background()
	root, err := os.MkdirTemp("", "pleno-git-history-bench-*")
	if err != nil {
		return err
	}
	defer func() {
		if root != "" {
			_ = os.RemoveAll(root)
		}
	}()

	spec := fixture.Spec{Commits: opts.commits, Files: opts.files}
	started := time.Now()
	meta, err := fixture.Generate(ctx, filepath.Join(root, "fixture.git"), spec)
	if err != nil {
		return fmt.Errorf("generate fixture: %w", err)
	}
	want := fixture.ExpectedInventory(spec)
	if meta.Inventory.Blobs != want.Blobs || meta.Inventory.Commits != want.Commits || meta.Inventory.Trees != want.Trees || meta.Inventory.Total != want.Total {
		return fmt.Errorf("fixture object inventory=%+v want=%+v", meta.Inventory, want)
	}
	fmt.Fprintf(os.Stderr, "git-history-bench: generated %d commits / %d objects in %s\n", opts.commits, meta.Inventory.Total, time.Since(started).Round(time.Millisecond))

	plenoBin, cleanup, err := resolvePlenoBinary(opts.plenoBin)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := os.Stat(opts.trufflehogBin); err != nil {
		return fmt.Errorf("pinned TruffleHog %q: %w (run `make bench-tools`)", opts.trufflehogBin, err)
	}

	measureCtx, cancel := context.WithTimeout(ctx, opts.commandTimeout)
	source, err := measureSource(measureCtx, meta, opts.window)
	cancel()
	if err != nil {
		return fmt.Errorf("source windows: %w", err)
	}

	tools, err := measureEndToEnd(ctx, meta, opts, plenoBin)
	if err != nil {
		return err
	}
	after, err := fixture.Inspect(ctx, meta.Repo)
	if err != nil {
		return fmt.Errorf("inspect fixture after scans: %w", err)
	}
	if after.Head != meta.Head || after.CanaryCommit != meta.CanaryCommit || after.Inventory != meta.Inventory {
		return fmt.Errorf("benchmark mutated fixture: before head=%s canary=%s inventory=%+v; after=%+v", meta.Head, meta.CanaryCommit, meta.Inventory, after)
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove runtime fixture: %w", err)
	}
	root = ""

	result := newResult(opts, meta, source, tools)
	if err := writeResults(opts.jsonOut, opts.markdownOut, result); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", opts.jsonOut, opts.markdownOut)
	if opts.enforce && !result.Gates.Pass {
		return errors.New("scheduled/manual thresholds failed; see git-history benchmark artifacts")
	}
	return nil
}

func parseOptions() (options, error) {
	var opts options
	flag.IntVar(&opts.commits, "commits", 4000, "number of deterministic commits (200000 produces exactly 1M objects)")
	flag.IntVar(&opts.files, "files", 4096, "steady-state file working set")
	flag.IntVar(&opts.window, "window", 0, "chunks per source timing window (default: commits/20, minimum 500)")
	flag.IntVar(&opts.warmups, "warmups", 1, "warmup scans per tool")
	flag.IntVar(&opts.runs, "runs", 4, "measured samples per tool; must be positive and even")
	flag.DurationVar(&opts.minSample, "min-sample", 2*time.Second, "minimum accumulated wall time per measured sample")
	flag.DurationVar(&opts.commandTimeout, "command-timeout", 20*time.Minute, "timeout for one source or tool scan")
	flag.BoolVar(&opts.enforce, "enforce", false, "fail when competitive speed or tail-stability thresholds miss")
	flag.StringVar(&opts.plenoBin, "pleno-dlp-bin", "", "prebuilt pleno-dlp binary (default: build this checkout)")
	flag.StringVar(&opts.trufflehogBin, "trufflehog-bin", "bench/.tools/trufflehog", "pinned TruffleHog binary")
	flag.StringVar(&opts.jsonOut, "json-out", "bench/results/git-history.json", "JSON result path")
	flag.StringVar(&opts.markdownOut, "markdown-out", "bench/results/git-history.md", "Markdown result path")
	flag.Parse()

	if opts.commits < 1 || opts.files < 1 {
		return options{}, errors.New("commits and files must be positive")
	}
	if opts.window == 0 {
		opts.window = opts.commits / 20
		if opts.window < 500 {
			opts.window = 500
		}
	}
	minimumWindows := 1 + 2*stabilityWindows
	if opts.window < 1 || opts.commits < minimumWindows*opts.window || opts.commits%opts.window != 0 {
		return options{}, fmt.Errorf("commits (%d) must be an exact multiple of window (%d) with at least %d windows", opts.commits, opts.window, minimumWindows)
	}
	if opts.warmups < 1 {
		return options{}, errors.New("warmups must be at least 1")
	}
	if opts.runs < 2 || opts.runs%2 != 0 {
		return options{}, errors.New("runs must be positive, even, and at least 2")
	}
	if opts.minSample <= 0 || opts.commandTimeout <= 0 {
		return options{}, errors.New("min-sample and command-timeout must be positive")
	}
	return opts, nil
}

func resolvePlenoBinary(override string) (string, func(), error) {
	noop := func() {}
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", noop, err
		}
		return override, noop, nil
	}
	dir, err := os.MkdirTemp("", "pleno-git-history-bin-*")
	if err != nil {
		return "", noop, err
	}
	bin := filepath.Join(dir, "pleno-dlp")
	if out, err := runBuild(bin); err != nil {
		os.RemoveAll(dir)
		return "", noop, fmt.Errorf("build pleno-dlp: %w: %s", err, out)
	}
	return bin, func() { os.RemoveAll(dir) }, nil
}

func runBuild(bin string) ([]byte, error) {
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/pleno-dlp")
	return cmd.CombinedOutput()
}
