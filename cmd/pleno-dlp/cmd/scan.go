// Package cmd hosts cobra subcommands for the pleno-dlp binary.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/custom"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/output"
	"github.com/plenoai/pleno-dlp/pkg/piidb"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/stdin"
	"github.com/plenoai/pleno-dlp/pkg/verify"
)

var Root = &cobra.Command{
	Use:           "pleno-dlp",
	Short:         "Scan sources for leaked secrets",
	SilenceUsage:  true,
	SilenceErrors: true,
}

var toolVersion string

func SetVersion(version, commit string) {
	toolVersion = version
	Root.Version = fmt.Sprintf("%s (%s)", version, commit)
}

// scanFlags holds flags shared by every source kind.
type scanFlags struct {
	format            string
	onlyVerified      bool
	noVerify          bool
	dropIndeterminate bool
	verifyRPS         int
	concurrency       int
	rulesPath         string
	failOn            string
	allowlistPath     string
	includeDetectors  []string
	excludeDetectors  []string
	quiet             bool
	revokeOnVerified  bool
	revokeDryRun      bool
	revokeSpool       string
	auditTrail        string
	blastRadiusOnly   bool
	showSuppressed    bool
	incremental       bool
	incrementalState  string
	cpuProfile        string
	piiEngine         string
	piiEngineCmd      string
	piiEnginePort     int
	piiEngineLanguage string
	piiEngineReady    time.Duration
	piiEngineRequest  time.Duration
	piiEngineDevice   string
	piiModel          string
	piiModelPath      string
}

var scanOpts scanFlags

// scanCmd is the parent command for source-specific subcommands.
var scanCmd = &cobra.Command{
	Use:   "scan <kind> [args...]",
	Short: "Scan a source for leaked secrets",
	Long: "Scan a source for leaked secrets. Supported kinds:\n" +
		"  filesystem  walk one or more local paths\n" +
		"  git         walk the commit history of a local git repo\n" +
		"  s3          walk objects in an S3 bucket (or S3-compatible store)\n" +
		"  stdin       read input from os.Stdin (e.g. `cat file | pleno-dlp scan stdin`)\n" +
		"  github      walk full commit history across every branch; optional REST issues/PRs/comments/gists and opt-in wikis/artifacts\n" +
		"  gitlab      walk GitLab API blobs; --include-comments scans MR notes/discussions\n" +
		"  forgejo|gitea|gogs|gitbucket|codeberg  scan issue comments via forge API\n" +
		"  onedev|codebase|pagure                  scan issue/PR comments via forge API\n" +
		"  sqldump     scan SQL dump files (mysqldump, pg_dump, sqlite3 .dump)",
}

var scanFilesystemCmd = &cobra.Command{
	Use:   "filesystem <path> [path...]",
	Short: "Scan local filesystem paths",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScanFilesystem,
}

type fsFlags struct {
	include                []string
	exclude                []string
	maxSizeBytes           int64
	disableDefaultExcludes bool
}

var fsOpts fsFlags

type gitFlags struct {
	repo                    string
	branch                  string
	since                   string
	maxDepth                int
	include                 []string
	exclude                 []string
	allOccurrences          bool
	includeCommitMetadata   bool
	skipMergeCommits        bool
	trufflehogCompatible    bool
	includeGitArchives      bool
	includeGitBinaries      bool
	gitArtifactMaxBytes     int64
	archiveMaxExpandedBytes int64
	archiveMaxFiles         int
	archiveMaxDepth         int
	archiveTimeout          time.Duration
}

var gitOpts gitFlags

var scanGitCmd = &cobra.Command{
	Use:   "git --repo <path>",
	Short: "Scan a local git repository's commit history",
	Args:  cobra.NoArgs,
	RunE:  runScanGit,
}

type stdinFlags struct {
	label    string
	maxBytes int64
}

var stdinOpts stdinFlags

var scanStdinCmd = &cobra.Command{
	Use:   "stdin",
	Short: "Scan input piped to standard input",
	Args:  cobra.NoArgs,
	RunE:  runScanStdin,
}

type sqldumpFlags struct {
	format         string
	includeTables  []string
	excludeTables  []string
	maxSizeBytes   int64
	maxLineBytes   int
	chunkLineCount int
}

var sqldumpOpts sqldumpFlags

var scanSQLDumpCmd = &cobra.Command{
	Use:   "sqldump <file> [file...]",
	Short: "Scan SQL dump files (mysqldump, pg_dump, sqlite3 .dump)",
	Long: "Scan SQL dump files for secrets. Supports mysqldump, pg_dump, and sqlite3 .dump formats.\n" +
		"Auto-detects the format from file headers; override with --dump-format.\n\n" +
		"Example (AWS RDS):\n" +
		"  mysqldump -h mydb.abc123.us-east-1.rds.amazonaws.com -u admin -p mydb > dump.sql\n" +
		"  pleno-dlp scan sqldump dump.sql",
	Args: cobra.MinimumNArgs(1),
	RunE: runScanSQLDump,
}

func init() {
	scanCmd.PersistentFlags().StringVar(&scanOpts.format, "format", "table", "output format: json, sarif, table")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.onlyVerified, "only-verified", false, "emit, count, and optionally revoke only provider-verified findings; findings whose verification attempt failed (network error, provider 5xx, rate limit) are kept as indeterminate by default — see --drop-indeterminate")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.noVerify, "no-verify", false,
		"skip every detector's network Verify() round-trip so the scan runs fully offline and fast. "+
			"Verification is never attempted, so every finding's verdict is unverified — not indeterminate; "+
			"indeterminate specifically means an attempt was made and failed (see --only-verified), which cannot "+
			"happen here. This trades confidence for latency, meant for latency-sensitive callers like "+
			"pre-commit/agent hooks (see pleno-dlp hooks install, issue #303), not for CI gating. Mutually "+
			"exclusive with --only-verified, which would otherwise always yield zero findings.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.dropIndeterminate, "drop-indeterminate", false,
		"with --only-verified, also drop findings whose verification attempt failed instead of keeping them as indeterminate. "+
			"The default keeps them: a failed verification attempt means liveness is unknown, not disproven, so dropping by "+
			"default would silently hide a possibly-live credential during a provider outage. Ignored without --only-verified.")
	scanCmd.PersistentFlags().IntVar(&scanOpts.verifyRPS, "verify-rps", 10, "per-host requests-per-second cap during verification (0 = disable rate limiting)")
	scanCmd.PersistentFlags().IntVar(&scanOpts.concurrency, "concurrency", 8, "number of scan workers")
	scanCmd.PersistentFlags().StringVar(&scanOpts.rulesPath, "rules", "", "path to a custom rules JSON file (org-specific patterns)")
	scanCmd.PersistentFlags().StringVar(&scanOpts.failOn, "fail-on", "high", "minimum severity that triggers exit 1: any|info|low|medium|high|critical "+
		"(default high: audit-first rollout — verified/critical and named unverified-secret findings gate CI; "+
		"generic-entropy, JWT, PEM, and PII findings default to medium and do not; pass any to gate on every finding, "+
		"including that lower tier, once the repo's baseline is clean)")
	scanCmd.PersistentFlags().StringVar(&scanOpts.allowlistPath, "allowlist", "", "path to a JSON allowlist file that mutes known false positives (auto-discovers .pleno-allow.json from the repo root)")
	scanCmd.PersistentFlags().StringSliceVar(&scanOpts.includeDetectors, "include-detectors", nil, "only run these detectors (comma-separated, case-insensitive Type names; see `pleno-dlp detectors list`). Custom rules from --rules count as GenericHighEntropy.")
	scanCmd.PersistentFlags().StringSliceVar(&scanOpts.excludeDetectors, "exclude-detectors", nil, "skip these detectors (comma-separated, case-insensitive Type names). Applied after --include-detectors.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.quiet, "quiet", false, "suppress the end-of-scan summary line on stderr (use in scripted callers parsing stderr)")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.revokeOnVerified, "revoke-on-verified", false,
		"after a finding verifies, immediately call the detector's Revoker to invalidate the secret upstream. "+
			"Refuses to run unless "+EnvAllowRevoke+"=1 is set in the environment so a misconfigured CI cannot accidentally revoke live credentials. Detectors without a Revoker implementation are skipped.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.revokeDryRun, "revoke-dry-run", false,
		"when used with --revoke-on-verified, log what would be revoked without contacting the provider")
	scanCmd.PersistentFlags().StringVar(&scanOpts.revokeSpool, "revoke-spool", "",
		"path to a JSONL spool file that captures verified findings whose detector supports revoke. "+
			"Decouples scan from revoke: replay later with `pleno-dlp revoke --revoke-from-spool <path>`. "+
			"The file holds raw secrets and is created mode 0600. "+
			"Requires "+EnvAllowRawExport+"=1 so a misconfigured CI cannot accidentally serialize live credentials. "+
			"Mutually exclusive with --revoke-on-verified.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.auditTrail, auditTrailFlagName, "", auditTrailFlagHelp+" Only applies with --revoke-on-verified.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.blastRadiusOnly, "blast-radius-only", false,
		"emit and count only findings the engine has tagged blast_radius=true "+
			"(driftwood-pattern flags: any *_privileged, *_high_value, or *_high_risk). "+
			"Combine with --fail-on to gate CI on high-impact leaks only.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.showSuppressed, "show-suppressed", false,
		"also emit findings the placeholder filter suppressed (tagged suppressed_by=\"placeholder\" in --format json/sarif, "+
			"a SUPPRESSED column in --format table), so a false-drop is falsifiable instead of silent (issue #290). "+
			"Suppressed findings never affect --fail-on / exit code or dedup — they bypass the counting chain entirely.")
	scanCmd.PersistentFlags().BoolVar(&scanOpts.incremental, "incremental", false,
		"skip the scan when source resources and scan configuration match the previous successful baseline")
	scanCmd.PersistentFlags().StringVar(&scanOpts.incrementalState, "incremental-state", ".pleno-dlp-incremental.json",
		"path to the incremental scan state file")
	scanCmd.PersistentFlags().StringVar(&scanOpts.cpuProfile, "cpu-profile", "", "write a Go CPU profile for the complete scan to this file (disabled by default)")

	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngine, "pii-engine", "off",
		"PII detection engine: 'off' disables PII detection; 'anonymize' spawns the pleno-anonymize HTTP server (requires uv + Python 3.12+); 'openai-pf-native' runs privacy-filter.cpp in-process and requires a binary built with the opf_native build tag. Mutually exclusive — choose one.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineCmd, "pii-engine-cmd",
		"pleno-dlp pii-server --port {PORT}",
		"argv to spawn the anonymize PII engine; the literal '{PORT}' is substituted with the chosen ephemeral loopback port. Defaults to 'pleno-dlp pii-server --port {PORT}'. 'pleno-dlp' as argv[0] is auto-resolved via os.Executable().")
	scanCmd.PersistentFlags().IntVar(&scanOpts.piiEnginePort, "pii-engine-port", 0,
		"loopback port for the anonymize PII engine (0 = auto-allocate).")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineLanguage, "pii-engine-language", "auto",
		"language hint passed to the anonymize PII engine: 'ja', 'en', or 'auto'.")
	scanCmd.PersistentFlags().DurationVar(&scanOpts.piiEngineReady, "pii-engine-ready-timeout", 0,
		"how long to wait for the anonymize engine's /ready endpoint before giving up and continuing without PII detection. 0 defaults to 60s.")
	scanCmd.PersistentFlags().DurationVar(&scanOpts.piiEngineRequest, "pii-engine-request-timeout", 10*time.Second,
		"per-request timeout for anonymize /api/analyze calls.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiEngineDevice, "pii-engine-device", "auto",
		"inference device for --pii-engine=openai-pf-native: 'auto' | 'cpu' | 'cuda' | 'mps'. 'auto' picks Metal on darwin and CPU on linux; 'mps' maps to Metal. Ignored by anonymize.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiModel, "pii-model", "q8",
		"GGUF weight variant for --pii-engine=openai-pf-native: 'q8' (default, ~1.5GB) or 'f16' (~2.6GB). Downloaded and cached under os.UserCacheDir()/pleno-dlp/models on first use, checksum-verified (a mismatch on a downloaded file is fatal). Ignored by other engines.")
	scanCmd.PersistentFlags().StringVar(&scanOpts.piiModelPath, "pii-model-path", "",
		"explicit path to a privacy-filter GGUF for --pii-engine=openai-pf-native, bypassing download and checksum verification (a user-supplied path is trusted; lets air-gapped operators pre-place the weights). Ignored by other engines.")

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
	scanGitCmd.Flags().BoolVar(&gitOpts.allOccurrences, "all-occurrences", false, "report every commit a secret appears in; default collapses to the introducing commit with extra_data.occurrence_count")
	scanGitCmd.Flags().BoolVar(&gitOpts.includeCommitMetadata, "include-commit-metadata", false, "scan commit messages, author/committer identities, and git notes (opt-in because identities contain expected PII)")
	scanGitCmd.Flags().BoolVar(&gitOpts.skipMergeCommits, "skip-merge-commits", false, "omit merge-commit diffs while retaining non-merge history")
	scanGitCmd.Flags().BoolVar(&gitOpts.trufflehogCompatible, "trufflehog-compatible", false, "match trufflehog's Git diff surface (omit merge/rename diffs and blank unchanged context)")
	scanGitCmd.Flags().BoolVar(&gitOpts.includeGitArchives, "include-git-archives", false, "expand and scan recognized archives in Git history within strict resource budgets")
	scanGitCmd.Flags().BoolVar(&gitOpts.includeGitBinaries, "include-git-binaries", false, "scan otherwise-binary blobs in Git history within strict resource budgets")
	scanGitCmd.Flags().Int64Var(&gitOpts.gitArtifactMaxBytes, "git-artifact-max-bytes", 10<<20, "maximum compressed archive or raw binary blob bytes")
	scanGitCmd.Flags().Int64Var(&gitOpts.archiveMaxExpandedBytes, "git-archive-max-expanded-bytes", 50<<20, "maximum total expanded archive bytes per changed blob")
	scanGitCmd.Flags().IntVar(&gitOpts.archiveMaxFiles, "git-archive-max-files", 1000, "maximum expanded files per changed archive")
	scanGitCmd.Flags().IntVar(&gitOpts.archiveMaxDepth, "git-archive-max-depth", 3, "maximum nested archive recursion depth")
	scanGitCmd.Flags().DurationVar(&gitOpts.archiveTimeout, "git-archive-timeout", 5*time.Second, "maximum archive expansion time per changed blob")
	_ = scanGitCmd.MarkFlagRequired("repo")

	scanStdinCmd.Flags().StringVar(&stdinOpts.label, "label", "", "label for the stdin input (rendered in output; default \"<stdin>\")")
	scanStdinCmd.Flags().Int64Var(&stdinOpts.maxBytes, "max-bytes", 0, "buffer cap for stdin (0 = default 64 MiB); excess input is truncated and the run exits non-zero")

	scanSQLDumpCmd.Flags().StringVar(&sqldumpOpts.format, "dump-format", "auto", "dump format: auto, mysql, postgres, sqlite")
	scanSQLDumpCmd.Flags().StringSliceVar(&sqldumpOpts.includeTables, "include-tables", nil, "only scan these tables (case-insensitive)")
	scanSQLDumpCmd.Flags().StringSliceVar(&sqldumpOpts.excludeTables, "exclude-tables", nil, "skip these tables (case-insensitive)")
	scanSQLDumpCmd.Flags().Int64Var(&sqldumpOpts.maxSizeBytes, "max-size", 0, "skip dump files larger than this many bytes (0 = default 512 MiB)")
	scanSQLDumpCmd.Flags().IntVar(&sqldumpOpts.maxLineBytes, "max-line-bytes", 0, "max bytes per line (0 = default 4 MiB); longer lines are skipped")
	scanSQLDumpCmd.Flags().IntVar(&sqldumpOpts.chunkLineCount, "chunk-lines", 0, "number of data lines per chunk (0 = default 50)")

	scanCmd.AddCommand(scanDockerCmd)
	scanCmd.AddCommand(scanFilesystemCmd)
	scanCmd.AddCommand(scanGCSCmd)
	scanCmd.AddCommand(scanGitCmd)
	scanCmd.AddCommand(scanS3Cmd)
	scanCmd.AddCommand(scanStdinCmd)
	scanCmd.AddCommand(scanSQLDumpCmd)
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
	// Stdin scans are pipe-only.
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
	for name, valid := range map[string]bool{
		"git-artifact-max-bytes": gitOpts.gitArtifactMaxBytes > 0, "git-archive-max-expanded-bytes": gitOpts.archiveMaxExpandedBytes > 0,
		"git-archive-max-files": gitOpts.archiveMaxFiles > 0, "git-archive-max-depth": gitOpts.archiveMaxDepth > 0, "git-archive-timeout": gitOpts.archiveTimeout > 0,
	} {
		if cmd.Flags().Changed(name) && !valid {
			return fmt.Errorf("git: --%s must be positive", name)
		}
	}
	if gitOpts.gitArtifactMaxBytes == 0 {
		gitOpts.gitArtifactMaxBytes = 10 << 20
	}
	if gitOpts.archiveMaxExpandedBytes == 0 {
		gitOpts.archiveMaxExpandedBytes = 50 << 20
	}
	if gitOpts.archiveMaxFiles == 0 {
		gitOpts.archiveMaxFiles = 1000
	}
	if gitOpts.archiveMaxDepth == 0 {
		gitOpts.archiveMaxDepth = 3
	}
	if gitOpts.archiveTimeout == 0 {
		gitOpts.archiveTimeout = 5 * time.Second
	}
	if gitOpts.gitArtifactMaxBytes < 0 || gitOpts.archiveMaxExpandedBytes < 0 || gitOpts.archiveMaxFiles < 0 || gitOpts.archiveMaxDepth < 0 || gitOpts.archiveTimeout < 0 {
		return errors.New("git: artifact limits must be positive")
	}
	if gitOpts.gitArtifactMaxBytes > 50<<20 || gitOpts.archiveMaxExpandedBytes > 200<<20 || gitOpts.archiveMaxFiles > 10000 || gitOpts.archiveMaxDepth > 8 || gitOpts.archiveTimeout > time.Minute {
		return errors.New("git: artifact limits exceed hard caps")
	}
	cfg, err := json.Marshal(map[string]any{
		"repo":                       gitOpts.repo,
		"branch":                     gitOpts.branch,
		"since":                      gitOpts.since,
		"max_depth":                  gitOpts.maxDepth,
		"include":                    gitOpts.include,
		"exclude":                    gitOpts.exclude,
		"include_commit_metadata":    gitOpts.includeCommitMetadata,
		"skip_merge_commits":         gitOpts.skipMergeCommits,
		"trufflehog_compatible":      gitOpts.trufflehogCompatible,
		"include_git_archives":       gitOpts.includeGitArchives,
		"include_git_binaries":       gitOpts.includeGitBinaries,
		"git_artifact_max_bytes":     gitOpts.gitArtifactMaxBytes,
		"archive_max_expanded_bytes": gitOpts.archiveMaxExpandedBytes,
		"archive_max_files":          gitOpts.archiveMaxFiles,
		"archive_max_depth":          gitOpts.archiveMaxDepth,
		"archive_timeout":            gitOpts.archiveTimeout,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "git")
}

func runScanSQLDump(cmd *cobra.Command, args []string) error {
	src := sources.New(sources.SourceSQLDump)
	if src == nil {
		return fmt.Errorf("sqldump source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"paths":            args,
		"format":           sqldumpOpts.format,
		"include_tables":   sqldumpOpts.includeTables,
		"exclude_tables":   sqldumpOpts.excludeTables,
		"max_size_bytes":   sqldumpOpts.maxSizeBytes,
		"max_line_bytes":   sqldumpOpts.maxLineBytes,
		"chunk_line_count": sqldumpOpts.chunkLineCount,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "sqldump")
}

// runScanCommon wires source init, engine execution, and output.
func runScanCommon(cmd *cobra.Command, src sources.Source, cfg []byte, kind string) (retErr error) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if scanOpts.noVerify && scanOpts.onlyVerified {
		return fmt.Errorf("--no-verify and --only-verified are mutually exclusive: with --no-verify no finding is ever verified, so --only-verified would always emit zero results")
	}
	// Reject an unknown --pii-engine as a hard config error rather than
	// letting startPIIEngine's error be swallowed by the "continue without
	// PII" downgrade below — otherwise a typo silently produces a
	// secret-only scan the operator reads as a full DLP pass.
	if !validPIIEngineMode(scanOpts.piiEngine) {
		return fmt.Errorf("unknown --pii-engine %q (valid: off, anonymize, openai-pf-native)", scanOpts.piiEngine)
	}
	// openai-pf-native needs the opf_native build tag. Hard-fail as a config
	// error here — a valid engine that this binary simply cannot provide —
	// so it is not swallowed by the "continue without PII" spawn-failure
	// downgrade below (ADR-0005 §F). nativeOPFBuilt is a build-tagged const.
	if strings.EqualFold(strings.TrimSpace(scanOpts.piiEngine), "openai-pf-native") && !nativeOPFBuilt {
		return errNativeNotBuilt
	}
	// --concurrency < 1 was silently clamped to 8 inside the engine, so
	// `--concurrency 0` scanned as if unset with no signal. Reject it here.
	if scanOpts.concurrency < 1 {
		return fmt.Errorf("--concurrency must be >= 1, got %d", scanOpts.concurrency)
	}
	if scanOpts.revokeOnVerified {
		if !scanOpts.revokeDryRun && os.Getenv(EnvAllowRevoke) != "1" {
			return fmt.Errorf("--revoke-on-verified refuses to run without %s=1 (irreversible operation; set the env var to opt in or pass --revoke-dry-run)", EnvAllowRevoke)
		}
	}
	if scanOpts.revokeSpool != "" {
		if scanOpts.revokeOnVerified {
			return fmt.Errorf("--revoke-spool is mutually exclusive with --revoke-on-verified (pick one trust model: inline revoke or deferred spool)")
		}
		if os.Getenv(EnvAllowRawExport) != "1" {
			return fmt.Errorf("--revoke-spool refuses to run without %s=1 (the spool file persists raw secrets to disk; set the env var to opt in)", EnvAllowRawExport)
		}
	}

	// The verify arg is the trufflehog Source contract, not a CLI option:
	// verification is unconditional.
	if err := src.Init(ctx, "cli", 0, 0, true, cfg, scanOpts.concurrency); err != nil {
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

	// per-repo / per-unit の partial flush。 source が IncrementalFlushSource
	// を実装していれば、 connector が unit 完了ごとにこの callback を呼ぶ。
	// callback の中で incremental state file を atomic に書き戻す。
	// scan が exit 非 0 で死んでも前回到達点までの state が残るので、 次回
	// 起動が resume できる。
	if incrementalKey != "" && incrementalState != nil {
		flush := sources.IncrementalFlushFunc(func(sourceState json.RawMessage) error {
			incrementalState.Entries[incrementalKey] = incrementalStateEntry{
				// A partial source checkpoint is resumable, but it does not
				// prove whole-resource coverage. Leaving this empty prevents the
				// next run from taking the unchanged-resource fast path before
				// failed units have been retried.
				ResourceFingerprint: "",
				ScannerFingerprint:  incrementalState.PendingScannerFingerprint,
				SourceState:         sourceState,
				UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
			}
			return saveIncrementalState(scanOpts.incrementalState, incrementalState)
		})
		if fs, ok := src.(sources.IncrementalFlushSource); ok {
			fs.SetIncrementalFlush(flush)
		}
	}

	// Install the per-host verify rate limiter. Verification always runs,
	// so this is unconditional. Detectors
	// all share http.DefaultTransport, so wrapping it here — once, before
	// any detector runs — covers the entire scan without per-detector
	// refactoring. We restore on exit so unit tests in the same process
	// aren't affected by leftover state.
	prev := verify.Install(scanOpts.verifyRPS)
	defer verify.Restore(prev)

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

	// chain owns Close/Flush for every sink tracked below, so wiring a
	// new buffering sink into this chain can never again silently drop
	// its output the way gitCrossCommitSink's did in #273 — see
	// engine.SinkChain and issue #282.
	chain := engine.NewSinkChain()
	chain.Track(sink)

	// suppressedAudit is the --show-suppressed extension point (#290):
	// when set, placeholder-suppressed findings are forwarded directly
	// to the raw output sink (tagged via Finding.SuppressedBy) instead
	// of only being tallied. Pointing it at sink rather than at
	// counter/piidbSink/etc. is deliberate — a suppressed finding must
	// still be visible for audit, but must not re-enter dedup, PII
	// classification, --only-verified, --blast-radius-only, or the
	// --fail-on gate the way a normal finding does.
	var suppressedAudit engine.Sink
	if scanOpts.showSuppressed {
		suppressedAudit = sink
	}

	// Wrap with the counting+dedup+placeholder+allowlist chain. Order
	// matters:
	//   - dedup is outermost so the counter only sees unique findings,
	//     which makes the exit code reflect what the user actually saw.
	//   - placeholder filter sits between dedup and allowlist so the
	//     well-known doc literals are gone before any user-curated
	//     allowlist entries are consulted. Users shouldn't have to
	//     enumerate vendor-docs placeholders in their own config.
	//   - allowlist sits inside placeholder so suppressed entries
	//     don't poison the dedup map (a different finding nearby
	//     should still emit).
	counter := &countingSink{inner: sink, threshold: threshold}
	chain.Track(counter)
	// PIIDB classification sits between counter and the upstream
	// chain. PII findings are buffered, classified in batch at Close,
	// then forwarded to counter with escalated severity so --fail-on
	// reflects the escalated level.
	piidbSink := piidb.NewSink(counter)
	chain.Track(piidbSink)
	// revokingSink wraps piidbSink when --revoke-on-verified is set.
	// PII findings are never verified so they pass through revoker
	// untouched; secrets that are verified get revoked before reaching
	// the PIIDB buffer.
	var topSink engine.Sink = piidbSink
	var revoker *revokingSink
	var spool *spoolSink
	if scanOpts.revokeOnVerified {
		auditW, closeAudit, err := openAuditTrail(cmd, scanOpts.auditTrail)
		if err != nil {
			return err
		}
		defer func() { _ = closeAudit() }()
		revoker = newRevokingSink(piidbSink, dets, scanOpts.revokeDryRun, cmd.ErrOrStderr(), auditW)
		topSink = chain.Track(revoker)
	}
	if scanOpts.revokeSpool != "" {
		spool, err = newSpoolSink(piidbSink, dets, scanOpts.revokeSpool, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		topSink = chain.Track(spool)
	}
	var onlyVerified *verifiedOnlySink
	if scanOpts.onlyVerified {
		onlyVerified = &verifiedOnlySink{inner: topSink, dropIndeterminate: scanOpts.dropIndeterminate}
		topSink = chain.Track(onlyVerified)
	}
	// --blast-radius-only sits OUTSIDE counter+revoker so the filter
	// happens first: non-blast-radius findings never reach the counter
	// (so they don't trigger exit 1) and never reach the user-facing
	// sink (so they don't print). With --fail-on critical, this means
	// CI gates on "is there a verified credential with elevated impact"
	// instead of "any finding at all".
	if scanOpts.blastRadiusOnly {
		topSink = chain.Track(&blastRadiusFilterSink{inner: topSink})
	}
	allowed := chain.Track(engine.NewAllowlist(allowlist, topSink))
	placeheld := chain.Track(engine.NewPlaceholderFilter(allowed, suppressedAudit))
	deduped := chain.Track(engine.NewDedup(placeheld))
	// Git-mode cross-commit dedup: collapse the same secret+file across many
	// commits to a single introducing-commit finding (with occurrence_count).
	// Wraps the per-location dedup so the counter only sees unique secrets.
	scanSink := deduped
	if kind == "git" && !gitOpts.allOccurrences {
		scanSink = chain.Track(engine.NewGitCrossCommitDedup(deduped))
	}
	defer func() { _ = chain.Close() }()
	defer func() {
		if n := engine.SuppressedCounter(allowed); n > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "allowlist: suppressed %d finding(s)\n", n)
		}
		if n := engine.PlaceholderSuppressedCounter(placeheld); n > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "placeholder: suppressed %d finding(s)\n", n)
		}
		// Not gated by --quiet: this is a signal about output
		// trustworthiness, not routine progress noise. A caller piping
		// --only-verified into an auto-rotate script needs to know some
		// results weren't actually confirmed dead — they just couldn't be
		// confirmed at all. See issue #246.
		if onlyVerified != nil {
			if n := onlyVerified.indeterminate.Load(); n > 0 {
				if scanOpts.dropIndeterminate {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"only-verified: dropped %d indeterminate finding(s) (verification attempt failed) due to --drop-indeterminate\n", n)
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"only-verified: kept %d indeterminate finding(s) — verification attempt failed (network error, provider 5xx, rate limit), so liveness is unknown rather than disproven; pass --drop-indeterminate to exclude them\n", n)
				}
			}
		}
	}()

	eng := engine.NewWithDetectors(dets, engine.Options{
		Concurrency: scanOpts.concurrency,
		NoVerify:    scanOpts.noVerify,
	}, scanSink)

	// Start only after every fallible configuration and output setup step.
	// A rejected invocation must never truncate an existing profile file.
	stopCPUProfile, err := startCPUProfile(scanOpts.cpuProfile)
	if err != nil {
		return err
	}
	defer func() {
		if err := stopCPUProfile(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()

	stats, err := eng.RunWithStats(ctx, src)
	var coverageErr *engine.DegradedError
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
		} else if errors.As(err, &coverageErr) {
			// Degraded coverage is non-zero, but not an immediate abort: source
			// units that succeeded already emitted valid findings and partial
			// incremental state. Flush/output/persist those before returning the
			// structured error so automation sees both the findings and the gap.
		} else {
			return fmt.Errorf("scan: %w", err)
		}
	}

	// Every buffering sink tracked into chain (git cross-commit dedup,
	// PIIDB classification, and any future addition) forwards its
	// buffered findings to counter here, before we read counter's state
	// below — without this, chain.Close()'s deferred cascade would still
	// reach them, but only after the summary line and exit code are
	// already computed. See issue #282.
	if err := chain.Flush(); err != nil {
		return fmt.Errorf("sink chain flush: %w", err)
	}

	// End-of-scan summary on stderr so it doesn't pollute --format json /
	// sarif output. Single line so scripts can parse it; --quiet skips
	// it for callers that prefer silence (eg structured pipelines).
	if !scanOpts.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"scanned %d chunk(s), %d byte(s), %d finding(s) in %s\n",
			stats.Chunks, stats.Bytes, counter.count.Load(), stats.Duration.Round(time.Millisecond),
		)
		if stats.VerificationCacheHits+stats.VerificationCacheMisses+stats.VerifiedDetectorCalls > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"verification cache: verdict_hits=%d missed_passes=%d partial_hits_wasted=%d bypasses=%d evictions=%d verified_passes_saved=%d verified_detector_calls=%d verified_call_time=%s\n",
				stats.VerificationCacheHits, stats.VerificationCacheMisses,
				stats.VerificationCacheHitsWasted, stats.VerificationCacheBypasses,
				stats.VerificationCacheEvictions,
				stats.VerifiedPassesSaved,
				stats.VerifiedDetectorCalls, stats.VerifiedDetectorCallDuration.Round(time.Millisecond),
			)
		}
		// Discoverability for the audit-first default (#250): when
		// some findings were emitted but didn't meet the --fail-on
		// gate, say so explicitly and name the escape hatch. Without
		// this, "exit 0 despite findings" reads as the scan silently
		// missing something rather than a deliberate, tunable policy.
		// In --fail-on=any mode every finding meets the gate, so below
		// is always 0 there and this never fires.
		if below := counter.count.Load() - counter.failing.Load(); below > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"exit gate: --fail-on=%s (%d %s finding(s) did not affect exit code; use --fail-on=any to block on all)\n",
				scanOpts.failOn, below, gateBelowLabel(threshold),
			)
		}
		if revoker != nil {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"revoke: attempted=%d revoked=%d failed=%d skipped-no-revoker=%d dry-run=%t\n",
				revoker.attempted.Load(), revoker.revoked.Load(), revoker.failed.Load(),
				revoker.skipped.Load(), scanOpts.revokeDryRun,
			)
		}
		if spool != nil {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"revoke-spool: queued=%d skipped-no-revoker=%d write-errors=%d path=%s\n",
				spool.queued.Load(), spool.skippedNoRv.Load(), spool.writeErrs.Load(), scanOpts.revokeSpool,
			)
		}
	}
	if incrementalKey != "" {
		var sourceState json.RawMessage
		if iss, ok := src.(sources.IncrementalStateSource); ok {
			sourceState = iss.IncrementalState()
		}
		resourceFingerprint := incrementalState.PendingResourceFingerprint
		if coverageErr != nil {
			resourceFingerprint = ""
		}
		incrementalState.Entries[incrementalKey] = incrementalStateEntry{
			ResourceFingerprint: resourceFingerprint,
			ScannerFingerprint:  incrementalState.PendingScannerFingerprint,
			SourceState:         sourceState,
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
	if coverageErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "coverage: status=degraded failures=%d source=%d archive=%d detector=%d\n",
			coverageErr.Total, coverageErr.Counts[engine.FailureSource], coverageErr.Counts[engine.FailureArchive], coverageErr.Counts[engine.FailureDetector])
		return fmt.Errorf("scan: %w", coverageErr)
	}

	if counter.failing.Load() > 0 {
		return errFindingsFound
	}
	return nil
}

func startCPUProfile(path string) (func() error, error) {
	if path == "" {
		return func() error { return nil }, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, fmt.Errorf("create CPU profile %q: %w", path, err)
	}
	tempPath := f.Name()
	removeTemp := func() error {
		err := os.Remove(tempPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("remove temporary CPU profile %q: %w", tempPath, err)
		}
		return nil
	}
	discard := func() error {
		closeErr := f.Close()
		if closeErr != nil {
			closeErr = fmt.Errorf("close temporary CPU profile %q: %w", tempPath, closeErr)
		}
		return errors.Join(closeErr, removeTemp())
	}
	if err := f.Chmod(0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure CPU profile %q: %w", path, err), discard())
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		return nil, errors.Join(fmt.Errorf("start CPU profile %q: %w", path, err), discard())
	}
	return func() error {
		pprof.StopCPUProfile()
		if err := f.Close(); err != nil {
			return errors.Join(fmt.Errorf("close CPU profile %q: %w", path, err), removeTemp())
		}
		if err := os.Rename(tempPath, path); err != nil {
			return errors.Join(fmt.Errorf("replace CPU profile %q: %w", path, err), removeTemp())
		}
		return nil
	}, nil
}

// filterDetectors narrows a detector slice by include / exclude name lists.
// Names are matched case-insensitively against DetectorType.String(). Both
// lists may contain comma-separated entries from cobra's StringSlice
// behaviour — those are already split for us.
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

// gateBelowLabel names the severities strictly below threshold, for the
// end-of-scan "exit gate" hint (#250). SeverityInfo is left out: no
// detector or built-in severity mapping currently emits it (DefaultSeverity
// only ever returns medium/high/critical; custom rules default to info only
// when a rule omits "severity" entirely), so listing it would name a
// category that's realistically always empty and read as noise.
func gateBelowLabel(threshold detectors.Severity) string {
	ordered := []detectors.Severity{
		detectors.SeverityLow, detectors.SeverityMedium, detectors.SeverityHigh, detectors.SeverityCritical,
	}
	var names []string
	for _, s := range ordered {
		if s < threshold {
			names = append(names, s.String())
		}
	}
	if len(names) == 0 {
		return "lower-severity"
	}
	return strings.Join(names, "/")
}

// isTerminalReader reports whether r is the process's terminal stdin.
// True only when r is *os.File AND that file is a character device — any
// other reader returns false so we don't accidentally block scripted
// callers.
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
	ResourceFingerprint string          `json:"resource_fingerprint"`
	ScannerFingerprint  string          `json:"scanner_fingerprint"`
	SourceState         json.RawMessage `json:"source_state,omitempty"`
	Chunks              int64           `json:"chunks"`
	Bytes               int64           `json:"bytes"`
	Findings            int64           `json:"findings"`
	Failing             int64           `json:"failing"`
	UpdatedAt           string          `json:"updated_at"`
}

func prepareIncremental(ctx context.Context, kind string, cfg []byte, src sources.Source) (string, *incrementalStateEntry, *incrementalStateFile, error) {
	if !scanOpts.incremental {
		return "", nil, nil, nil
	}
	fp, ok := src.(sources.ResourceFingerprinter)
	if !ok {
		return "", nil, nil, fmt.Errorf("--incremental is not supported for %s source", kind)
	}
	if !scanOpts.quiet {
		fmt.Fprintf(os.Stderr, "incremental: fingerprinting %s resources\n", kind)
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
	// 空 fingerprint は「安価な全体 fingerprint が存在しない」という
	// source からの opt-out。 skip
	// fast-path だけを諦め、 per-unit incremental は SourceState 経由で
	// そのまま効かせる。
	if ok && resourceFP != "" && entry.ResourceFingerprint == resourceFP && entry.ScannerFingerprint == scannerFP {
		return key, &entry, state, nil
	}
	if iss, supportsIncrementalState := src.(sources.IncrementalStateSource); supportsIncrementalState {
		if ok {
			if err := iss.SetIncrementalState(entry.SourceState); err != nil {
				return "", nil, nil, fmt.Errorf("incremental: configure %s source state: %w", kind, err)
			}
		} else if err := iss.SetIncrementalState(nil); err != nil {
			return "", nil, nil, fmt.Errorf("incremental: configure %s source state: %w", kind, err)
		}
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
		"only_verified":       scanOpts.onlyVerified,
		"no_verify":           scanOpts.noVerify,
		"drop_indeterminate":  scanOpts.dropIndeterminate,
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
		"pii_model":           scanOpts.piiModel,
		"pii_model_path":      scanOpts.piiModelPath,
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
	// per-repo の partial flush が頻繁に走るため、 reader が中途半端な
	// JSON を見ないように temp file → rename で atomic 化する。 同一
	// FS なら rename は POSIX で atomic。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("incremental: write state tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("incremental: rename state: %w", err)
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

// verifiedOnlySink filters to provider-confirmed findings, but treats the
// three verification verdicts differently rather than collapsing to a
// boolean (issue #246):
//   - Verified: always forwarded — that's the whole point of the flag.
//   - Indeterminate (verification attempt failed: network error, provider
//     5xx, rate limit): forwarded by default. The provider never actually
//     said "not live" — dropping it here would be indistinguishable from
//     "no secret found" for a live credential caught in a transient
//     outage. --drop-indeterminate opts back into the strict pre-#246
//     behaviour for callers that would rather under-report than see an
//     unconfirmed finding.
//   - Unverified (provider confirmed the secret is not live): always
//     dropped — this is the case --only-verified exists to filter out.
type verifiedOnlySink struct {
	inner             engine.Sink
	dropIndeterminate bool
	dropped           atomic.Int64
	indeterminate     atomic.Int64
}

func (v *verifiedOnlySink) Emit(f engine.Finding) {
	switch f.Result.Verdict() {
	case detectors.VerdictVerified:
		v.inner.Emit(f)
	case detectors.VerdictIndeterminate:
		v.indeterminate.Add(1)
		if v.dropIndeterminate {
			v.dropped.Add(1)
			return
		}
		v.inner.Emit(f)
	default:
		v.dropped.Add(1)
	}
}

func (v *verifiedOnlySink) Close() error { return v.inner.Close() }

// Execute is a thin wrapper main.go invokes. Returning instead of calling
// os.Exit here keeps the cmd package testable.
func Execute(ctx context.Context) error {
	return Root.ExecuteContext(ctx)
}
