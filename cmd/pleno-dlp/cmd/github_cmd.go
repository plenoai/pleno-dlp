package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// githubFlags collects the subset of GitHub Config that surfaces as CLI
// flags.
type githubFlags struct {
	org                       string
	repo                      string
	token                     string
	apiBase                   string
	appID                     string
	appInstallationID         string
	appPrivateKey             string
	appPrivateKeyFile         string
	includeComments           bool
	repoConcurrency           int
	repoWalkTimeout           time.Duration
	includeCommitMetadata     bool
	includeGitArchives        bool
	includeGitBinaries        bool
	gitArtifactMaxBytes       int64
	archiveMaxExpandedBytes   int64
	archiveMaxFiles           int
	archiveMaxDepth           int
	archiveTimeout            time.Duration
	includeRepoGlobs          []string
	excludeRepoGlobs          []string
	includeForks              bool
	includeArchived           bool
	expandMembers             bool
	commentsTimeframeDays     int
	includeIssues             bool
	includePullRequests       bool
	collabTimeframeDays       int
	includeWikis              bool
	gistURLs                  []string
	includeAuthenticatedGists bool
	includeGistComments       bool
	stateRetentionDays        int
	stateRetentionRuns        int
}

var (
	scanGitHubOpts   githubFlags
	verifyGitHubOpts githubFlags
)

var scanGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Scan a GitHub org or single repo (full commit history by default)",
	Long: "Scan a GitHub org or single repo. Reads --token, falling back to the GITHUB_TOKEN env var.\n" +
		"--org and --repo are mutually exclusive; one is required. Use --api-base for GitHub Enterprise.\n" +
		"Each repo is cloned and its full commit history across every branch is scanned. Repository history costs zero REST calls per repo; optional collaboration and gist surfaces use REST.",
	Args: cobra.NoArgs,
	RunE: runScanGitHub,
}

var verifyCmd = &cobra.Command{
	Use:   "verify <connector>",
	Short: "Verify a SaaS connector's token against its upstream provider",
	Long: "Verify a SaaS connector's token against its upstream provider.\n" +
		"Returns exit 0 when the provider confirms the token, exit 1 otherwise.",
}

var verifyGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Verify GitHub token or GitHub App credentials",
	Args:  cobra.NoArgs,
	RunE:  runVerifyGitHub,
}

func init() {
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.org, "org", "", "GitHub organisation login to scan (mutually exclusive with --repo)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.repo, "repo", "", "single GitHub repository in owner/name form (mutually exclusive with --org)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.token, "token", "", "GitHub PAT or installation token (falls back to the GITHUB_TOKEN env var)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.apiBase, "api-base", "", "GitHub API base URL (default https://api.github.com; override for GitHub Enterprise)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.appID, "app-id", "", "GitHub App ID (falls back to the GITHUB_APP_ID env var)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.appInstallationID, "app-installation-id", "", "GitHub App installation ID (falls back to the GITHUB_APP_INSTALLATION_ID env var)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.appPrivateKeyFile, "app-private-key-file", "", "path to GitHub App PEM private key (falls back to the GITHUB_APP_PRIVATE_KEY_FILE env var)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeComments, "include-comments", false, "also scan issue comments and pull request review comments")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.repoConcurrency, "repo-concurrency", 1, "maximum concurrent GitHub repository clone/walk workers (independent of --concurrency)")
	scanGitHubCmd.Flags().DurationVar(&scanGitHubOpts.repoWalkTimeout, "repo-walk-timeout", 0, "maximum Git history walk time per repository (0 = unbounded; clone time is excluded)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeCommitMetadata, "include-commit-metadata", false, "scan commit messages, author/committer identities, and git notes (opt-in because identities contain expected PII)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeGitArchives, "include-git-archives", false, "expand and scan recognized archives in Git history within strict resource budgets")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeGitBinaries, "include-git-binaries", false, "scan otherwise-binary blobs in Git history within strict resource budgets")
	scanGitHubCmd.Flags().Int64Var(&scanGitHubOpts.gitArtifactMaxBytes, "git-artifact-max-bytes", 10<<20, "maximum compressed archive or raw binary blob bytes")
	scanGitHubCmd.Flags().Int64Var(&scanGitHubOpts.archiveMaxExpandedBytes, "git-archive-max-expanded-bytes", 50<<20, "maximum total expanded archive bytes per changed blob")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.archiveMaxFiles, "git-archive-max-files", 1000, "maximum expanded files per changed archive")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.archiveMaxDepth, "git-archive-max-depth", 3, "maximum nested archive recursion depth")
	scanGitHubCmd.Flags().DurationVar(&scanGitHubOpts.archiveTimeout, "git-archive-timeout", 5*time.Second, "maximum archive expansion time per changed blob")
	scanGitHubCmd.Flags().StringSliceVar(&scanGitHubOpts.includeRepoGlobs, "include-repo", nil, "repository glob to include (repeatable; matches owner/name)")
	scanGitHubCmd.Flags().StringSliceVar(&scanGitHubOpts.excludeRepoGlobs, "exclude-repo", nil, "repository glob to exclude (repeatable; matches owner/name)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeForks, "include-forks", true, "include fork repositories")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeArchived, "include-archived", true, "include archived repositories")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.expandMembers, "expand-members", false, "also scan repositories owned by organisation members")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.commentsTimeframeDays, "comments-timeframe-days", 0, "only scan comments updated in the last N days (0 scans all)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeIssues, "include-issues", false, "scan issue titles and bodies (separate from comments)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includePullRequests, "include-pull-requests", false, "scan pull request titles and bodies (separate from comments)")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.collabTimeframeDays, "collaboration-timeframe-days", 0, "only scan issues and pull requests updated in the last N days (0 scans all)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeWikis, "include-wikis", false, "scan each enabled repository wiki as an independent Git history unit")
	scanGitHubCmd.Flags().StringSliceVar(&scanGitHubOpts.gistURLs, "gist", nil, "explicit gist URL or ID to scan (repeatable)")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeAuthenticatedGists, "include-authenticated-gists", false, "scan gists visible to the authenticated user")
	scanGitHubCmd.Flags().BoolVar(&scanGitHubOpts.includeGistComments, "include-gist-comments", false, "scan comments for selected gists (separate opt-in)")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.stateRetentionDays, "state-retention-days", 30, "minimum age before pruning unobserved GitHub repository state")
	scanGitHubCmd.Flags().IntVar(&scanGitHubOpts.stateRetentionRuns, "state-retention-runs", 3, "minimum complete scans before pruning unobserved GitHub repository state")
	scanCmd.AddCommand(scanGitHubCmd)

	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.token, "token", "", "GitHub PAT (falls back to the GITHUB_TOKEN env var)")
	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.apiBase, "api-base", "", "GitHub API base URL (default https://api.github.com; override for GitHub Enterprise)")
	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.appID, "app-id", "", "GitHub App ID (falls back to the GITHUB_APP_ID env var)")
	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.appInstallationID, "app-installation-id", "", "GitHub App installation ID (falls back to the GITHUB_APP_INSTALLATION_ID env var)")
	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.appPrivateKeyFile, "app-private-key-file", "", "path to GitHub App PEM private key (falls back to the GITHUB_APP_PRIVATE_KEY_FILE env var)")
	verifyCmd.AddCommand(verifyGitHubCmd)
	Root.AddCommand(verifyCmd)
}

func runScanGitHub(cmd *cobra.Command, _ []string) error {
	if scanGitHubOpts.org == "" && scanGitHubOpts.repo == "" && len(scanGitHubOpts.gistURLs) == 0 && !scanGitHubOpts.includeAuthenticatedGists {
		return errors.New("github: one of --org, --repo, --gist, or --include-authenticated-gists is required")
	}
	for name, valid := range map[string]bool{
		"git-artifact-max-bytes": scanGitHubOpts.gitArtifactMaxBytes > 0, "git-archive-max-expanded-bytes": scanGitHubOpts.archiveMaxExpandedBytes > 0,
		"git-archive-max-files": scanGitHubOpts.archiveMaxFiles > 0, "git-archive-max-depth": scanGitHubOpts.archiveMaxDepth > 0, "git-archive-timeout": scanGitHubOpts.archiveTimeout > 0,
	} {
		if cmd.Flags().Changed(name) && !valid {
			return fmt.Errorf("github: --%s must be positive", name)
		}
	}
	cfg, err := scanGitHubConfig(scanGitHubOpts)
	if err != nil {
		return err
	}
	src, err := connectors.AsSource("github", cfg)
	if err != nil {
		return err
	}
	return runScanCommon(cmd, src, nil, "github")
}

// runVerifyGitHub looks up the github connector and dispatches the token
// to its Verify function. cfg carries --api-base so the verify call lands
// on the right base URL for GitHub Enterprise installs.
func runVerifyGitHub(cmd *cobra.Command, _ []string) error {
	c, ok := connectors.Get("github")
	if !ok {
		return errors.New("github connector is not registered")
	}
	if c.Verify == nil {
		return errors.New("github connector does not implement verify")
	}
	cfg, token, err := verifyGitHubConfig(verifyGitHubOpts)
	if err != nil {
		return err
	}
	verified, err := c.Verify(cmdContext(cmd), cfg, token)
	if err != nil {
		return fmt.Errorf("github: verify: %w", err)
	}
	if !verified {
		fmt.Fprintln(cmd.OutOrStdout(), "github: token NOT verified (401 / 403)")
		return errVerifyFailed
	}
	fmt.Fprintln(cmd.OutOrStdout(), "github: token verified")
	return nil
}

func resolveGitHubToken(explicit string) string {
	return resolveEnv(explicit, "GITHUB_TOKEN")
}

func scanGitHubConfig(opts githubFlags) (connectors.Config, error) {
	if opts.stateRetentionDays == 0 {
		opts.stateRetentionDays = 30
	}
	if opts.stateRetentionRuns == 0 {
		opts.stateRetentionRuns = 3
	}
	repoConcurrency := opts.repoConcurrency
	if repoConcurrency == 0 {
		repoConcurrency = 1
	}
	if opts.commentsTimeframeDays < 0 {
		return nil, fmt.Errorf("github: --comments-timeframe-days must be non-negative, got %d", opts.commentsTimeframeDays)
	}
	if opts.repoWalkTimeout < 0 {
		return nil, fmt.Errorf("github: --repo-walk-timeout must be non-negative, got %s", opts.repoWalkTimeout)
	}
	if opts.gitArtifactMaxBytes == 0 {
		opts.gitArtifactMaxBytes = 10 << 20
	}
	if opts.archiveMaxExpandedBytes == 0 {
		opts.archiveMaxExpandedBytes = 50 << 20
	}
	if opts.archiveMaxFiles == 0 {
		opts.archiveMaxFiles = 1000
	}
	if opts.archiveMaxDepth == 0 {
		opts.archiveMaxDepth = 3
	}
	if opts.archiveTimeout == 0 {
		opts.archiveTimeout = 5 * time.Second
	}
	if opts.gitArtifactMaxBytes < 0 || opts.archiveMaxExpandedBytes < 0 || opts.archiveMaxFiles < 0 || opts.archiveMaxDepth < 0 || opts.archiveTimeout < 0 {
		return nil, errors.New("github: artifact limits must be positive")
	}
	if opts.gitArtifactMaxBytes > 50<<20 || opts.archiveMaxExpandedBytes > 200<<20 || opts.archiveMaxFiles > 10000 || opts.archiveMaxDepth > 8 || opts.archiveTimeout > time.Minute {
		return nil, errors.New("github: artifact limits exceed hard caps")
	}
	if opts.collabTimeframeDays < 0 {
		return nil, fmt.Errorf("github: --collaboration-timeframe-days must be non-negative, got %d", opts.collabTimeframeDays)
	}
	cfg := connectors.Config{
		"org":                         opts.org,
		"repo":                        opts.repo,
		"api_base":                    opts.apiBase,
		"include_comments":            fmt.Sprintf("%t", opts.includeComments),
		"repo_concurrency":            fmt.Sprintf("%d", repoConcurrency),
		"repo_walk_timeout":           opts.repoWalkTimeout.String(),
		"include_commit_metadata":     fmt.Sprintf("%t", opts.includeCommitMetadata),
		"include_git_archives":        fmt.Sprintf("%t", opts.includeGitArchives),
		"include_git_binaries":        fmt.Sprintf("%t", opts.includeGitBinaries),
		"git_artifact_max_bytes":      fmt.Sprintf("%d", opts.gitArtifactMaxBytes),
		"archive_max_expanded_bytes":  fmt.Sprintf("%d", opts.archiveMaxExpandedBytes),
		"archive_max_files":           fmt.Sprintf("%d", opts.archiveMaxFiles),
		"archive_max_depth":           fmt.Sprintf("%d", opts.archiveMaxDepth),
		"archive_timeout":             opts.archiveTimeout.String(),
		"include_repo_globs":          strings.Join(opts.includeRepoGlobs, "\n"),
		"exclude_repo_globs":          strings.Join(opts.excludeRepoGlobs, "\n"),
		"include_forks":               fmt.Sprintf("%t", opts.includeForks),
		"include_archived":            fmt.Sprintf("%t", opts.includeArchived),
		"expand_members":              fmt.Sprintf("%t", opts.expandMembers),
		"comments_timeframe_days":     fmt.Sprintf("%d", opts.commentsTimeframeDays),
		"include_issues":              fmt.Sprintf("%t", opts.includeIssues),
		"include_pull_requests":       fmt.Sprintf("%t", opts.includePullRequests),
		"collab_timeframe_days":       fmt.Sprintf("%d", opts.collabTimeframeDays),
		"include_wikis":               fmt.Sprintf("%t", opts.includeWikis),
		"gist_urls":                   strings.Join(opts.gistURLs, "\n"),
		"include_authenticated_gists": fmt.Sprintf("%t", opts.includeAuthenticatedGists),
		"include_gist_comments":       fmt.Sprintf("%t", opts.includeGistComments),
		"state_retention_days":        fmt.Sprintf("%d", opts.stateRetentionDays),
		"state_retention_runs":        fmt.Sprintf("%d", opts.stateRetentionRuns),
	}
	if repoConcurrency < 1 || repoConcurrency > 32 {
		return nil, fmt.Errorf("github: --repo-concurrency must be between 1 and 32, got %d", repoConcurrency)
	}
	token := resolveGitHubToken(opts.token)
	appID := resolveEnv(opts.appID, "GITHUB_APP_ID")
	appInstallationID := resolveEnv(opts.appInstallationID, "GITHUB_APP_INSTALLATION_ID")
	appPrivateKey := resolveEnv(opts.appPrivateKey, "GITHUB_APP_PRIVATE_KEY")
	appPrivateKeyFile := resolveEnv(opts.appPrivateKeyFile, "GITHUB_APP_PRIVATE_KEY_FILE")
	hasAppConfig := appID != "" || appInstallationID != "" || appPrivateKey != "" || appPrivateKeyFile != ""
	if token != "" && hasAppConfig {
		return nil, errors.New("github: --token and GitHub App credentials are mutually exclusive")
	}
	if token == "" && !hasAppConfig {
		return nil, errors.New("github: --token or GitHub App credentials are required")
	}
	if token != "" {
		cfg["token"] = token
		return cfg, nil
	}
	cfg["app_id"] = appID
	cfg["app_installation_id"] = appInstallationID
	cfg["app_private_key"] = appPrivateKey
	cfg["app_private_key_file"] = appPrivateKeyFile
	return cfg, nil
}

func verifyGitHubConfig(opts githubFlags) (connectors.Config, string, error) {
	cfg := connectors.Config{"api_base": opts.apiBase}
	token := resolveGitHubToken(opts.token)
	appID := resolveEnv(opts.appID, "GITHUB_APP_ID")
	appInstallationID := resolveEnv(opts.appInstallationID, "GITHUB_APP_INSTALLATION_ID")
	appPrivateKey := resolveEnv(opts.appPrivateKey, "GITHUB_APP_PRIVATE_KEY")
	appPrivateKeyFile := resolveEnv(opts.appPrivateKeyFile, "GITHUB_APP_PRIVATE_KEY_FILE")
	hasAppConfig := appID != "" || appInstallationID != "" || appPrivateKey != "" || appPrivateKeyFile != ""
	if token != "" && hasAppConfig {
		return nil, "", errors.New("github: --token and GitHub App credentials are mutually exclusive")
	}
	if token == "" && !hasAppConfig {
		return nil, "", errors.New("github: --token or GitHub App credentials are required")
	}
	if token != "" {
		return cfg, token, nil
	}
	cfg["app_id"] = appID
	cfg["app_installation_id"] = appInstallationID
	cfg["app_private_key"] = appPrivateKey
	cfg["app_private_key_file"] = appPrivateKeyFile
	return cfg, "", nil
}

var errVerifyFailed = errors.New("verify failed")

func IsVerifyError(err error) bool { return err == errVerifyFailed }

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
