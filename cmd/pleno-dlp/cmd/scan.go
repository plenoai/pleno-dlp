// Package cmd hosts cobra subcommands for the pleno-dlp binary.
// Each subcommand registers itself with Root from a package-level init(),
// so adding a command means adding one file here — not editing main.go.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/custom"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/output"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/stdin"
	"github.com/plenoai/pleno-dlp/pkg/verify"
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

// toolVersion holds the bare semver string injected by the linker (e.g.
// "1.2.3") so it can be embedded in SARIF output and the incremental-scan
// fingerprint without parsing Root.Version.
var toolVersion string

// SetVersion lets main.go inject build-time version/commit metadata after
// linker flags resolve. Keeping it out of init() ordering avoids races with
// subcommand registration.
func SetVersion(version, commit string) {
	toolVersion = version
	Root.Version = fmt.Sprintf("%s (%s)", version, commit)
}

// scanFlags holds flags that apply across every source kind. Per-source
// flags (paths, repo, since, ...) live on the corresponding subcommand to
// keep cobra's --help output narrow and to give each kind its own validation.
type scanFlags struct {
	format           string
	verify           bool
	verifyRPS        int
	concurrency      int
	rulesPath        string
	failOn           string
	allowlistPath    string
	includeDetectors []string
	excludeDetectors []string
	quiet            bool
	revokeOnVerified bool
	revokeDryRun     bool
	blastRadiusOnly  bool
	incremental      bool
	incrementalState string
	// piiEngine selects the PII engine integration. "off" (default)
	// preserves the historical single-binary UX: the anonymize
	// detector is registered but the supervisor handle stays nil,
	// so it returns no findings and incurs no spawn cost. "anonymize"
	// spawns the pleno-anonymize HTTP server for the duration of the
	// scan and routes PII detection through it.
	piiEngine         string
	piiEngineCmd      string
	piiEnginePort     int
	piiEngineLanguage string
	piiEngineReady    time.Duration
	piiEngineRequest  time.Duration
	// piiEngineDevice is the inference device hint forwarded to the
	// openai-pf engine. Ignored when --pii-engine != openai-pf. Kept
	// on the shared flag set rather than under a per-engine namespace
	// so future engines can reuse the same operator-facing knob.
	piiEngineDevice string
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
		"  git         walk the commit history of a local git repo\n" +
		"  stdin       read input from os.Stdin (e.g. `cat file | pleno-dlp scan stdin`)\n" +
		"  github      walk every default-branch blob in a GitHub org or single repo; --include-comments scans issue/PR comments\n" +
		"  gitlab      walk GitLab API blobs; --include-comments scans MR notes/discussions\n" +
		"  forgejo|gitea|gogs|gitbucket|codeberg  scan issue comments via forge API\n" +
		"  onedev|codebase|pagure                  scan issue/PR comments via forge API",
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

// fsFlags captures filesystem-specific configuration. Mirrors gitOpts
// so users get the same --include/--exclude vocabulary across kinds.
type fsFlags struct {
	include                []string
	exclude                []string
	maxSizeBytes           int64
	disableDefaultExcludes bool
}

var fsOpts fsFlags

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

// stdinFlags captures stdin-specific options. Label rides through to
// StdinMeta.Label so output formatters render something more useful than
// the default "<stdin>" placeholder.
type stdinFlags struct {
	label    string
	maxBytes int64
}

var stdinOpts stdinFlags

// scanStdinCmd reads a single chunk from os.Stdin. We refuse to attach a
// terminal — a TTY on stdin is almost certainly a user mistake (forgot to
// pipe), and silently waiting for input wedges scripts.
var scanStdinCmd = &cobra.Command{
	Use:   "stdin",
	Short: "Scan input piped to standard input",
	Args:  cobra.NoArgs,
	RunE:  runScanStdin,
}

func init() {
	// Persistent flags on scanCmd so every subcommand inherits them — keeps
	// `scan filesystem --format json` and `scan git --format json` consistent.
	scanCmd.PersistentFlags().StringVar(&scanOpts.format, "format", "table", "output format: json, sarif, table")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.verify, "verify", false, "verify candidate secrets against upstream APIs")
	scanCmd.PersistentFlags().IntVar(&scanOpts.verifyRPS, "verify-rps", 10, "per-host requests-per-second cap during --verify (0 = disable rate limiting)")
	scanCmd.PersistentFlags().IntVar(&scanOpts.concurrency, "concurrency", 8, "number of scan workers")
	scanCmd.PersistentFlags().StringVar(&scanOpts.rulesPath, "rules", "", "path to a custom rules JSON file (org-specific patterns)")
	scanCmd.PersistentFlags().StringVar(&scanOpts.failOn, "fail-on", "any", "minimum severity that triggers exit 1: any|info|low|medium|high|critical")
	scanCmd.PersistentFlags().StringVar(&scanOpts.allowlistPath, "allowlist", "", "path to a JSON allowlist file that mutes known false positives (auto-discovers .pleno-allow.json from the repo root)")
	scanCmd.PersistentFlags().StringSliceVar(&scanOpts.includeDetectors, "include-detectors", nil, "only run these detectors (comma-separated, case-insensitive Type names; see `pleno-dlp detectors list`). Custom rules from --rules count as GenericHighEntropy.")
	scanCmd.PersistentFlags().StringSliceVar(&scanOpts.excludeDetectors, "exclude-detectors", nil, "skip these detectors (comma-separated, case-insensitive Type names). Applied after --include-detectors.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.quiet, "quiet", false, "suppress the end-of-scan summary line on stderr (use in scripted callers parsing stderr)")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.revokeOnVerified, "revoke-on-verified", false,
		"after a finding verifies, immediately call the detector's Revoker to invalidate the secret upstream. "+
			"Requires --verify. Refuses to run unless "+EnvAllowRevoke+"=1 is set in the environment so a misconfigured CI cannot accidentally revoke live credentials. Detectors without a Revoker implementation are skipped.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.revokeDryRun, "revoke-dry-run", false,
		"when used with --revoke-on-verified, log what would be revoked without contacting the provider")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.blastRadiusOnly, "blast-radius-only", false,
		"emit and count only findings the engine has tagged blast_radius=true "+
			"(driftwood-pattern flags: any *_privileged, *_high_value, or *_high_risk). "+
			"Combine with --fail-on to gate CI on high-impact leaks only.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.incremental, "incremental", false,
		"skip the scan when source resources and scan configuration match the previous successful baseline")
	scanCmd.PersistentFlags().StringVar(&scanOpts.incrementalState, "incremental-state", ".pleno-dlp-incremental.json",
		"path to the incremental scan state file")

	// PII engine flags. Default is "off" so the binary keeps its
	// single-process UX for users without uvx / Python on PATH.
	// When --pii-engine=anonymize, runScanCommon spawns the supervisor
	// before the scan and tears it down after.
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngine, "pii-engine", "off",
		"PII detection engine: 'off' disables PII detection; 'anonymize' spawns the pleno-anonymize HTTP server (ja-first NER, fast cold start); 'openai-pf' spawns the openai/privacy-filter wrapper (1.5B-param MoE classifier, GPU-recommended). Both require uv + Python 3.12+ on PATH. Mutually exclusive — choose one.")
	// pii-engine-cmd default is the anonymize argv. When --pii-engine=openai-pf
	// is selected and the operator did NOT override this flag, startPIIEngine
	// substitutes the openai-pf default (`pleno-dlp openai-pf-server --port
	// {PORT}`). Surfacing one cobra default that's wrong for the other
	// engine is acceptable because explicit operator overrides are the
	// common case for non-default engines; the help text says so.
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineCmd, "pii-engine-cmd",
		"pleno-dlp pii-server --port {PORT}",
		"argv to spawn the PII engine; the literal '{PORT}' is substituted with the chosen ephemeral loopback port. When unset, defaults match the selected engine: 'pleno-dlp pii-server --port {PORT}' for anonymize, 'pleno-dlp openai-pf-server --port {PORT}' for openai-pf. 'pleno-dlp' as argv[0] is auto-resolved via os.Executable() so the spawn finds the running binary regardless of how it was installed.")
	scanCmd.PersistentFlags().IntVar(&scanOpts.piiEnginePort, "pii-engine-port", 0,
		"loopback port for the PII engine (0 = auto-allocate). Used by anonymize and openai-pf.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineLanguage, "pii-engine-language", "auto",
		"language hint passed to the PII engine: 'ja', 'en', or 'auto' (let the engine pick). Only used when --pii-engine=anonymize (openai-pf does its own language inference).")
	scanCmd.PersistentFlags().DurationVar(&scanOpts.piiEngineReady, "pii-engine-ready-timeout", 0,
		"how long to wait for the PII engine's /ready endpoint before giving up and continuing the scan without PII detection. 0 = engine default (60s for anonymize, 300s for openai-pf — opf's cold-path includes a multi-GB HuggingFace download).")
	scanCmd.PersistentFlags().DurationVar(&scanOpts.piiEngineRequest, "pii-engine-request-timeout", 10*time.Second,
		"per-request timeout for /api/analyze calls to the PII engine. Used by anonymize and openai-pf.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineDevice, "pii-engine-device", "auto",
		"inference device hint for --pii-engine=openai-pf: 'auto' | 'cpu' | 'cuda' | 'mps'. Ignored by anonymize.")

	scanFilesystemCmd.Flags().StringSliceVar(&fsOpts.include, "include", nil, "glob(s) to include (matched against root-relative paths and basenames)")
	scanFilesystemCmd.Flags().StringSliceVar(&fsOpts.exclude, "exclude", nil, "glob(s) to exclude (in addition to default excludes)")
	scanFilesystemCmd.Flags().Int64Var(&fsOpts.maxSizeBytes, "max-size", 0, "skip files larger than this many bytes (0 = default 10 MiB)")
	scanFilesystemCmd.Flags().BoolVar(&fsOpts.disableDefaultExcludes, "no-default-excludes", false, "disable default excludes (.git, node_modules, vendor, target, ...)")

	scanGitCmd.Flags().StringVar(&gitOpts.repo, "repo", "", "absolute or relative path to a local git repository")
	scanGitCmd.Flags().StringVar(&gitOpts.branch, "branch", "", "branch to walk (default: HEAD)")
	scanGitCmd.Flags().StringVar(&gitOpts.since, "since", "", "RFC3339 cutoff; commits older than this are skipped")
	scanGitCmd.Flags().IntVar(&gitOpts.maxDepth, "max-depth", 0, "cap on commits walked (0 = unbounded)")
	scanGitCmd.Flags().StringSliceVar(&gitOpts.include, "include", nil, "glob(s) to include (matched against repo-relative paths)")
	scanGitCmd.Flags().StringSliceVar(&gitOpts.exclude, "exclude", nil, "glob(s) to exclude")
	_ = scanGitCmd.MarkFlagRequired("repo")

	scanStdinCmd.Flags().StringVar(&stdinOpts.label, "label", "", "label for the stdin input (rendered in output; default \"<stdin>\")")
	scanStdinCmd.Flags().Int64Var(&stdinOpts.maxBytes, "max-bytes", 0, "buffer cap for stdin (0 = default 64 MiB); excess input is truncated and the run exits non-zero")

	scanCmd.AddCommand(scanFilesystemCmd)
	scanCmd.AddCommand(scanGitCmd)
	scanCmd.AddCommand(scanStdinCmd)
	Root.AddCommand(scanCmd)
}

func runScanFilesystem(cmd *cobra.Command, args []string) error {
	src := sources.New(sources.SourceFilesystem)
	if src == nil {
		return fmt.Errorf("filesystem source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"paths":                    args,
		"include":                  fsOpts.include,
		"exclude":                  fsOpts.exclude,
		"max_size_bytes":           fsOpts.maxSizeBytes,
		"disable_default_excludes": fsOpts.disableDefaultExcludes,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "filesystem")
}

func runScanStdin(cmd *cobra.Command, _ []string) error {
	// Refuse to block on a TTY. Stdin scans are pipe-only by design;
	// silently waiting for keyboard input is an almost-certain bug in
	// the caller's pipeline. The check is best-effort — non-files (eg
	// in tests, where we hand a Buffer to runStdinScan via cmd.SetIn)
	// won't fail this guard because their Stat fails outright.
	if isTerminalReader(cmd.InOrStdin()) {
		return fmt.Errorf("stdin source: refusing to read from a terminal — pipe input via `cmd | pleno-dlp scan stdin`")
	}
	src := sources.New(sources.SourceStdin)
	if src == nil {
		return fmt.Errorf("stdin source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"label":     stdinOpts.label,
		"max_bytes": stdinOpts.maxBytes,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	// Pass cmd.InOrStdin() through to the source so cobra-level rebinding
	// (cmd.SetIn) reaches the reader; production stays on os.Stdin.
	if r := cmd.InOrStdin(); r != nil {
		if setter, ok := src.(interface{ SetReader(io.Reader) }); ok {
			setter.SetReader(r)
		}
	}
	return runScanCommon(cmd, src, cfg, "stdin")
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

	// --revoke-on-verified gate (issue #73): refuse early if the
	// environment isn't explicitly opted-in. We do this before any I/O
	// so a misconfigured CI fails fast with a clear message rather
	// than silently scanning and then silently skipping revocation.
	if scanOpts.revokeOnVerified {
		if !scanOpts.verify {
			return fmt.Errorf("--revoke-on-verified requires --verify (revoking unverified candidates would be unsafe)")
		}
		if !scanOpts.revokeDryRun && os.Getenv(EnvAllowRevoke) != "1" {
			return fmt.Errorf("--revoke-on-verified refuses to run without %s=1 (irreversible operation; set the env var to opt in or pass --revoke-dry-run)", EnvAllowRevoke)
		}
	}

	if err := src.Init(ctx, "cli", 0, 0, scanOpts.verify, cfg, scanOpts.concurrency); err != nil {
		return fmt.Errorf("init %s source: %w", kind, err)
	}

	dets, err := filterDetectors(detectors.All(), scanOpts.includeDetectors, scanOpts.excludeDetectors)
	if err != nil {
		return err
	}
	// Custom rules pass through unfiltered: --rules is an explicit opt-in,
	// so the operator already chose to run them. Filtering would also be
	// awkward — custom rules all share Type=GenericHighEntropy, so an
	// `--include-detectors aws` would silently drop every custom rule.
	if scanOpts.rulesPath != "" {
		extra, err := custom.LoadFile(scanOpts.rulesPath)
		if err != nil {
			return err
		}
		for _, d := range extra {
			dets = append(dets, d)
		}
	}

	threshold, err := parseFailOn(scanOpts.failOn)
	if err != nil {
		return err
	}

	allowlist, err := loadAllowlistMaybe(scanOpts.allowlistPath)
	if err != nil {
		return err
	}
	incrementalKey, incrementalEntry, incrementalState, err := prepareIncremental(ctx, kind, cfg, src)
	if err != nil {
		return err
	}
	if incrementalEntry != nil {
		if !scanOpts.quiet {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"incremental: unchanged resources; skipped scan (previous chunks=%d bytes=%d findings=%d)\n",
				incrementalEntry.Chunks, incrementalEntry.Bytes, incrementalEntry.Findings,
			)
		}
		if incrementalEntry.Failing > 0 {
			return errFindingsFound
		}
		return nil
	}

	// Install the per-host verify rate limiter when --verify is on.
	// Detectors all share http.DefaultTransport, so wrapping it here
	// — once, before any detector runs — covers the entire scan
	// without per-detector refactoring. We restore on exit so unit
	// tests in the same process aren't affected by leftover state.
	if scanOpts.verify {
		prev := verify.Install(scanOpts.verifyRPS)
		defer verify.Restore(prev)
	}

	// PII engine lifecycle. When --pii-engine=anonymize is set, spawn
	// the pleno-anonymize HTTP server and publish it via the
	// package-level handle so the anonymize detector can dispatch
	// chunks against it. Spawn failure is downgraded to a single
	// stderr warning + skip; we never abort the secret scan because
	// the PII side-channel is unavailable.
	if stopPII, err := startPIIEngine(ctx, cmd, cmd.ErrOrStderr()); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "pii-engine: %v — continuing without PII detection\n", err)
	} else if stopPII != nil {
		defer stopPII()
	}

	sink, err := output.NewSink(scanOpts.format, cmd.OutOrStdout(), toolVersion)
	if err != nil {
		return err
	}

	// Wrap with the counting+dedup+placeholder+allowlist chain. Order
	// matters:
	//   - dedup is outermost so the counter only sees unique findings,
	//     which makes the exit code reflect what the user actually saw.
	//   - placeholder filter sits between dedup and allowlist so the
	//     well-known doc literals (AKIAIOSFODNN7EXAMPLE, YOUR_TOKEN,
	//     XXXXXXXX, …) are gone before any user-curated allowlist
	//     entries are consulted. Users shouldn't have to enumerate
	//     vendor-docs placeholders in their own config.
	//   - allowlist sits inside placeholder so suppressed entries
	//     don't poison the dedup map (a different finding nearby
	//     should still emit).
	counter := &countingSink{inner: sink, threshold: threshold}
	// revokingSink wraps the counter when --revoke-on-verified is set.
	// It sits BETWEEN allowlist and counter so allowlisted (false-positive)
	// findings never trigger a real revocation, but the counter still
	// reflects the original finding count for exit-code purposes.
	var topSink engine.Sink = counter
	var revoker *revokingSink
	if scanOpts.revokeOnVerified {
		revoker = newRevokingSink(counter, dets, scanOpts.revokeDryRun, cmd.ErrOrStderr())
		topSink = revoker
	}
	// --blast-radius-only sits OUTSIDE counter+revoker so the filter
	// happens first: non-blast-radius findings never reach the counter
	// (so they don't trigger exit 1) and never reach the user-facing
	// sink (so they don't print). With --fail-on critical, this means
	// CI gates on "is there a verified credential with elevated impact"
	// instead of "any finding at all".
	if scanOpts.blastRadiusOnly {
		topSink = &blastRadiusFilterSink{inner: topSink}
	}
	allowed := engine.NewAllowlist(allowlist, topSink)
	placeheld := engine.NewPlaceholderFilter(allowed)
	deduped := engine.NewDedup(placeheld)
	defer func() { _ = sink.Close() }()
	defer func() {
		if n := engine.SuppressedCounter(allowed); n > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "allowlist: suppressed %d finding(s)\n", n)
		}
		if n := engine.PlaceholderSuppressedCounter(placeheld); n > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "placeholder: suppressed %d finding(s)\n", n)
		}
	}()

	eng := engine.NewWithDetectors(dets, engine.Options{
		Verify:      scanOpts.verify,
		Concurrency: scanOpts.concurrency,
	}, deduped)

	stats, err := eng.RunWithStats(ctx, src)
	if err != nil {
		// Stdin truncation is not a fatal scan error: the chunk that was
		// read (up to --max-bytes) has already been scanned and any
		// findings already counted. Treating it as fatal would discard
		// the summary and clobber the findings exit code. Warn on stderr
		// and fall through so the summary prints and errFindingsFound is
		// driven from the finding counter. Any other error is fatal.
		if stdin.IsTruncationError(err) {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"stdin: input exceeded max_bytes; trailing data was not scanned (raise --max-bytes to scan it all)\n")
		} else {
			return fmt.Errorf("scan: %w", err)
		}
	}

	// End-of-scan summary on stderr so it doesn't pollute --format json /
	// sarif output. Single line so scripts can parse it; --quiet skips
	// it for callers that prefer silence (eg structured pipelines).
	if !scanOpts.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"scanned %d chunk(s), %d byte(s), %d finding(s) in %s\n",
			stats.Chunks, stats.Bytes, counter.count.Load(), stats.Duration.Round(time.Millisecond),
		)
		if revoker != nil {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"revoke: attempted=%d revoked=%d failed=%d skipped-no-revoker=%d dry-run=%t\n",
				revoker.attempted.Load(), revoker.revoked.Load(), revoker.failed.Load(),
				revoker.skipped.Load(), scanOpts.revokeDryRun,
			)
		}
	}
	if incrementalKey != "" {
		incrementalState.Entries[incrementalKey] = incrementalStateEntry{
			ResourceFingerprint: incrementalState.PendingResourceFingerprint,
			ScannerFingerprint:  incrementalState.PendingScannerFingerprint,
			Chunks:              stats.Chunks,
			Bytes:               stats.Bytes,
			Findings:            counter.count.Load(),
			Failing:             counter.failing.Load(),
			UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
		}
		if err := saveIncrementalState(scanOpts.incrementalState, incrementalState); err != nil {
			return err
		}
	}

	if counter.failing.Load() > 0 {
		return errFindingsFound
	}
	return nil
}

// filterDetectors narrows a detector slice by include / exclude name lists.
// Names are matched case-insensitively against DetectorType.String(). Both
// lists may contain comma-separated entries from cobra's StringSlice
// behaviour (the user typed `--include-detectors aws,github`) — those are
// already split for us.
//
// Validation: an unknown name returns an error rather than silently doing
// nothing. Typos in CI configs would otherwise emit zero findings without
// any signal — exactly the false-confidence failure mode this scanner
// exists to prevent.
//
// Order: include first (treated as an allowlist; empty means "all"), then
// exclude removes from that result. Both nil → return as-is.
func filterDetectors(in []detectors.Detector, include, exclude []string) ([]detectors.Detector, error) {
	if len(include) == 0 && len(exclude) == 0 {
		return in, nil
	}
	known := map[string]struct{}{}
	for _, d := range in {
		known[strings.ToLower(d.Type().String())] = struct{}{}
	}
	normalise := func(names []string, label string) (map[string]struct{}, error) {
		set := make(map[string]struct{}, len(names))
		for _, raw := range names {
			n := strings.ToLower(strings.TrimSpace(raw))
			if n == "" {
				continue
			}
			if _, ok := known[n]; !ok {
				return nil, fmt.Errorf("--%s: unknown detector %q (run `pleno-dlp detectors list --format names` to see registered types)", label, raw)
			}
			set[n] = struct{}{}
		}
		return set, nil
	}
	incSet, err := normalise(include, "include-detectors")
	if err != nil {
		return nil, err
	}
	excSet, err := normalise(exclude, "exclude-detectors")
	if err != nil {
		return nil, err
	}
	out := make([]detectors.Detector, 0, len(in))
	for _, d := range in {
		name := strings.ToLower(d.Type().String())
		if len(incSet) > 0 {
			if _, ok := incSet[name]; !ok {
				continue
			}
		}
		if _, drop := excSet[name]; drop {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// parseFailOn turns the --fail-on string into a Severity threshold. The
// special value "any" means any finding (severity > Unknown) trips the
// gate — this preserves the historical behaviour for callers that don't
// pass --fail-on explicitly.
func parseFailOn(s string) (detectors.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any":
		// Sentinel: every finding trips the gate. Implemented in
		// countingSink as "trip on count > 0" rather than a severity
		// comparison, so the threshold returned here doesn't matter
		// once the failing-count logic checks it. Return Info to keep
		// types tidy.
		return detectors.SeverityInfo, nil
	case "info":
		return detectors.SeverityInfo, nil
	case "low":
		return detectors.SeverityLow, nil
	case "medium":
		return detectors.SeverityMedium, nil
	case "high":
		return detectors.SeverityHigh, nil
	case "critical":
		return detectors.SeverityCritical, nil
	default:
		return 0, fmt.Errorf("--fail-on: unknown value %q (valid: any, info, low, medium, high, critical)", s)
	}
}

// isTerminalReader reports whether r is the process's terminal stdin.
// True only when r is *os.File AND that file is a character device — any
// other reader (test buffer, piped file, redirected fd) returns false so
// we don't accidentally block scripted callers.
func isTerminalReader(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// loadAllowlistMaybe loads the allowlist file at explicitPath when set,
// otherwise auto-discovers `.pleno-allow.json` walking up from the
// process's cwd. Returns (nil, nil) when neither is present so the
// engine layer's nil-allowlist pass-through kicks in.
//
// Auto-discovery walks up to 8 directories (covers nested monorepos
// without scanning the entire filesystem). The first match wins.
func loadAllowlistMaybe(explicitPath string) (*engine.Allowlist, error) {
	path := discoverAllowlistPath(explicitPath)
	if path == "" {
		return nil, nil
	}
	return engine.LoadAllowlistFile(path)
}

func discoverAllowlistPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := wd
	for i := 0; i < 8; i++ {
		candidate := dir + string(os.PathSeparator) + ".pleno-allow.json"
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := dirParent(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

type incrementalStateFile struct {
	Version                    int                              `json:"version"`
	Entries                    map[string]incrementalStateEntry `json:"entries"`
	PendingResourceFingerprint string                           `json:"-"`
	PendingScannerFingerprint  string                           `json:"-"`
}

type incrementalStateEntry struct {
	ResourceFingerprint string `json:"resource_fingerprint"`
	ScannerFingerprint  string `json:"scanner_fingerprint"`
	Chunks              int64  `json:"chunks"`
	Bytes               int64  `json:"bytes"`
	Findings            int64  `json:"findings"`
	Failing             int64  `json:"failing"`
	UpdatedAt           string `json:"updated_at"`
}

func prepareIncremental(ctx context.Context, kind string, cfg []byte, src sources.Source) (string, *incrementalStateEntry, *incrementalStateFile, error) {
	if !scanOpts.incremental {
		return "", nil, nil, nil
	}
	fp, ok := src.(sources.ResourceFingerprinter)
	if !ok {
		return "", nil, nil, fmt.Errorf("--incremental is not supported for %s source", kind)
	}
	resourceFP, err := fp.ResourceFingerprint(ctx)
	if err != nil {
		return "", nil, nil, fmt.Errorf("incremental: fingerprint %s source: %w", kind, err)
	}
	scannerFP, err := scannerFingerprint(kind, cfg)
	if err != nil {
		return "", nil, nil, err
	}
	state, err := loadIncrementalState(scanOpts.incrementalState)
	if err != nil {
		return "", nil, nil, err
	}
	key := kind + ":" + scannerFP
	entry, ok := state.Entries[key]
	if ok && entry.ResourceFingerprint == resourceFP && entry.ScannerFingerprint == scannerFP {
		return key, &entry, state, nil
	}
	state.PendingResourceFingerprint = resourceFP
	state.PendingScannerFingerprint = scannerFP
	return key, nil, state, nil
}

func scannerFingerprint(kind string, cfg []byte) (string, error) {
	rulesHash, err := fileContentHash(scanOpts.rulesPath)
	if err != nil {
		return "", fmt.Errorf("incremental: hash --rules: %w", err)
	}
	allowlistHash, err := fileContentHash(discoverAllowlistPath(scanOpts.allowlistPath))
	if err != nil {
		return "", fmt.Errorf("incremental: hash allowlist: %w", err)
	}
	payload := map[string]any{
		"version":             1,
		"tool_version":        toolVersion,
		"kind":                kind,
		"source_config":       json.RawMessage(cfg),
		"verify":              scanOpts.verify,
		"verify_rps":          scanOpts.verifyRPS,
		"rules_path":          scanOpts.rulesPath,
		"rules_hash":          rulesHash,
		"fail_on":             scanOpts.failOn,
		"allowlist_path":      discoverAllowlistPath(scanOpts.allowlistPath),
		"allowlist_hash":      allowlistHash,
		"include_detectors":   scanOpts.includeDetectors,
		"exclude_detectors":   scanOpts.excludeDetectors,
		"blast_radius_only":   scanOpts.blastRadiusOnly,
		"pii_engine":          scanOpts.piiEngine,
		"pii_engine_cmd":      scanOpts.piiEngineCmd,
		"pii_engine_language": scanOpts.piiEngineLanguage,
		"pii_engine_device":   scanOpts.piiEngineDevice,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func fileContentHash(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func loadIncrementalState(path string) (*incrementalStateFile, error) {
	state := &incrementalStateFile{Version: 1, Entries: map[string]incrementalStateEntry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, fmt.Errorf("incremental: read state: %w", err)
	}
	if len(data) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("incremental: parse state: %w", err)
	}
	if state.Entries == nil {
		state.Entries = map[string]incrementalStateEntry{}
	}
	state.Version = 1
	return state, nil
}

func saveIncrementalState(path string, state *incrementalStateFile) error {
	if state == nil {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("incremental: create state dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("incremental: encode state: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("incremental: write state: %w", err)
	}
	return nil
}

// dirParent returns dir's parent. Inlined here rather than depending on
// path/filepath.Dir to keep the auto-discovery loop transparent — Dir's
// behaviour at root differs subtly across platforms and we want the
// loop bound to win, not Dir's edge cases.
func dirParent(dir string) string {
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == os.PathSeparator {
			if i == 0 {
				return string(os.PathSeparator)
			}
			return dir[:i]
		}
	}
	return dir
}

// errFindingsFound is the sentinel used to signal "scan succeeded but
// secrets were found". main.go maps this to exit code 1.
var errFindingsFound = fmt.Errorf("findings detected")

// IsFindingsError reports whether err is the findings sentinel. main.go
// uses this to choose its exit code without importing the variable directly.
func IsFindingsError(err error) bool { return err == errFindingsFound }

// countingSink is a tiny pass-through that tallies forwarded findings
// and how many of them met the --fail-on severity gate. Lives here
// rather than pkg/engine because exit-code policy is a CLI concern —
// the engine itself has no opinion on exit codes.
type countingSink struct {
	inner     engine.Sink
	threshold detectors.Severity
	count     atomic.Int64
	failing   atomic.Int64
}

func (c *countingSink) Emit(f engine.Finding) {
	c.count.Add(1)
	if f.Result.Severity >= c.threshold {
		c.failing.Add(1)
	}
	c.inner.Emit(f)
}

func (c *countingSink) Close() error { return c.inner.Close() }

// blastRadiusFilterSink drops every finding that doesn't carry
// ExtraData["blast_radius"]=="true". Findings reach this sink only when
// --blast-radius-only is set. The engine's cross-cutting rollup (see
// pkg/engine.tagBlastRadius) is what populates that field from the
// per-provider *_privileged / *_high_value / *_high_risk flags, so this
// filter doesn't have to know the per-provider vocabulary.
type blastRadiusFilterSink struct {
	inner   engine.Sink
	dropped atomic.Int64
}

func (b *blastRadiusFilterSink) Emit(f engine.Finding) {
	if f.Result.ExtraData["blast_radius"] != "true" {
		b.dropped.Add(1)
		return
	}
	b.inner.Emit(f)
}

func (b *blastRadiusFilterSink) Close() error { return b.inner.Close() }

// Execute is a thin wrapper main.go invokes. Returning instead of calling
// os.Exit here keeps the cmd package testable.
func Execute(ctx context.Context) error {
	return Root.ExecuteContext(ctx)
}
