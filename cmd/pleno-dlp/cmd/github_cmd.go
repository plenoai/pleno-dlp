package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// githubFlags collects the subset of GitHub Config that surfaces as CLI
// flags. The rest of the connector's Config (max_blob_bytes / concurrency)
// is intentionally omitted from the v1 surface — those land alongside
// follow-up source surfaces.
type githubFlags struct {
	org     string
	repo    string
	token   string
	apiBase string
}

var (
	scanGitHubOpts   githubFlags
	verifyGitHubOpts githubFlags
)

var scanGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Scan a GitHub org or single repo (default-branch blobs)",
	Long: "Scan a GitHub org or single repo. Reads --token, falling back to the GITHUB_TOKEN env var.\n" +
		"--org and --repo are mutually exclusive; one is required. Use --api-base for GitHub Enterprise.",
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
	Short: "Verify a GitHub PAT (calls GET /user)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyGitHub,
}

func init() {
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.org, "org", "", "GitHub organisation login to scan (mutually exclusive with --repo)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.repo, "repo", "", "single GitHub repository in owner/name form (mutually exclusive with --org)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.token, "token", "", "GitHub PAT (falls back to the GITHUB_TOKEN env var)")
	scanGitHubCmd.Flags().StringVar(&scanGitHubOpts.apiBase, "api-base", "", "GitHub API base URL (default https://api.github.com; override for GitHub Enterprise)")
	scanCmd.AddCommand(scanGitHubCmd)

	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.token, "token", "", "GitHub PAT (falls back to the GITHUB_TOKEN env var)")
	verifyGitHubCmd.Flags().StringVar(&verifyGitHubOpts.apiBase, "api-base", "", "GitHub API base URL (default https://api.github.com; override for GitHub Enterprise)")
	verifyCmd.AddCommand(verifyGitHubCmd)
	Root.AddCommand(verifyCmd)
}

func runScanGitHub(cmd *cobra.Command, _ []string) error {
	if scanGitHubOpts.org == "" && scanGitHubOpts.repo == "" {
		return errors.New("github: one of --org or --repo is required")
	}
	token := resolveGitHubToken(scanGitHubOpts.token)
	if token == "" {
		return errors.New("github: --token is required (or set the GITHUB_TOKEN env var)")
	}
	cfg := connectors.Config{
		"token":    token,
		"org":      scanGitHubOpts.org,
		"repo":     scanGitHubOpts.repo,
		"api_base": scanGitHubOpts.apiBase,
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
	token := resolveGitHubToken(verifyGitHubOpts.token)
	if token == "" {
		return errors.New("github: --token is required (or set the GITHUB_TOKEN env var)")
	}
	c, ok := connectors.Get("github")
	if !ok {
		return errors.New("github connector is not registered")
	}
	if c.Verify == nil {
		return errors.New("github connector does not implement verify")
	}
	cfg := connectors.Config{"api_base": verifyGitHubOpts.apiBase}
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
	if explicit != "" {
		return explicit
	}
	return os.Getenv("GITHUB_TOKEN")
}

var errVerifyFailed = errors.New("verify failed")

func IsVerifyError(err error) bool { return err == errVerifyFailed }

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
