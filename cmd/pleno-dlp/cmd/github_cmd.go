package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// githubFlags collects the subset of GitHub Config that surfaces as CLI
// flags. The rest of the connector's Config (max_blob_bytes / concurrency)
// is intentionally omitted from the v1 surface — those land alongside
// follow-up source surfaces.
type githubFlags struct {
	org               string
	repo              string
	token             string
	apiBase           string
	appID             string
	appInstallationID string
	appPrivateKey     string
	appPrivateKeyFile string
	includeComments   bool
	scanMode          string
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
		"--scan-mode history (default) clones each repo and scans every commit on every branch with\n" +
		"zero REST cost per repo; --scan-mode tree scans only default-branch blobs via the REST API.",
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
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.scanMode, "scan-mode", "history", "scan mode: history (full commit history, clone-based) or tree (default-branch blobs via REST)")
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
	if scanGitHubOpts.org == "" && scanGitHubOpts.repo == "" {
		return errors.New("github: one of --org or --repo is required")
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
	cfg := connectors.Config{
		"org":              opts.org,
		"repo":             opts.repo,
		"api_base":         opts.apiBase,
		"scan_mode":        opts.scanMode,
		"include_comments": fmt.Sprintf("%t", opts.includeComments),
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
