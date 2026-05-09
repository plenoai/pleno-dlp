package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// githubFlags collects the subset of GitHub Config that surfaces as CLI
// flags. The rest of the connector's Config (include_issues / include_prs
// / max_blob_bytes) is intentionally omitted from the v1 surface — those
// land alongside the follow-up source surfaces.
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

// scanGitHubCmd: `pleno-dlp scan github --org acme [--api-base ...]`.
// Runs the standard runScanCommon pipeline against the GitHub connector.
var scanGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Scan a GitHub org or single repo (default-branch blobs)",
	Long: "Scan a GitHub org or single repo. Reads --token, falling back to the GITHUB_TOKEN env var.\n" +
		"--org and --repo are mutually exclusive; one is required. Use --api-base for GitHub Enterprise.",
	Args: cobra.NoArgs,
	RunE: runScanGitHub,
}

// verifyCmd is the parent of provider-specific verify subcommands. It
// only routes to subcommands; running it bare prints help so users land
// on a valid path quickly.
var verifyCmd = &cobra.Command{
	Use:   "verify <connector>",
	Short: "Verify a SaaS connector's token against its upstream provider",
	Long: "Verify a SaaS connector's token against its upstream provider.\n" +
		"Returns exit 0 when the provider confirms the token, exit 1 otherwise.",
}

// verifyGitHubCmd: `pleno-dlp verify github [--token ... | $GITHUB_TOKEN]`.
// Calls GET /user via the connector's Verify and renders the result.
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

// runScanGitHub translates flags + GITHUB_TOKEN into a Config JSON blob
// and hands the rest to runScanCommon — the same path filesystem / git
// already use. The connector self-validates org/repo mutual exclusivity
// inside Init, so the CLI only enforces "we have a token at all".
func runScanGitHub(cmd *cobra.Command, _ []string) error {
	if scanGitHubOpts.org == "" && scanGitHubOpts.repo == "" {
		return errors.New("github: one of --org or --repo is required")
	}
	token := resolveGitHubToken(scanGitHubOpts.token)
	if token == "" {
		return errors.New("github: --token is required (or set the GITHUB_TOKEN env var)")
	}
	src := sources.New(sources.SourceGitHub)
	if src == nil {
		return errors.New("github source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"token":    token,
		"org":      scanGitHubOpts.org,
		"repo":     scanGitHubOpts.repo,
		"api_base": scanGitHubOpts.apiBase,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "github")
}

// runVerifyGitHub builds the connector via the registry, plumbs the
// (optional) api-base override through SetAPIBase, and dispatches the
// configured token to the connector's Verify method. We deliberately
// look up via connectors.New("github") rather than importing the
// concrete package so the dispatcher generalises trivially when more
// `verify <connector>` subcommands land.
func runVerifyGitHub(cmd *cobra.Command, _ []string) error {
	token := resolveGitHubToken(verifyGitHubOpts.token)
	if token == "" {
		return errors.New("github: --token is required (or set the GITHUB_TOKEN env var)")
	}
	c := connectors.New("github")
	if c == nil {
		return errors.New("github connector is not registered (missing pkg/sources/all import?)")
	}
	if !c.Descriptor().Capabilities.Has(connectors.CapVerify) {
		return errors.New("github connector does not advertise CapVerify (registry / capability mismatch)")
	}
	if setter, ok := c.(interface{ SetAPIBase(string) }); ok && verifyGitHubOpts.apiBase != "" {
		setter.SetAPIBase(verifyGitHubOpts.apiBase)
	}
	v, ok := c.(connectors.Verifier)
	if !ok {
		return errors.New("github connector does not implement Verifier despite CapVerify (registry drift)")
	}
	verified, err := v.Verify(cmdContext(cmd), token)
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

// resolveGitHubToken implements the documented fallback: explicit --token
// flag wins; otherwise the GITHUB_TOKEN env var is consulted; otherwise
// the empty string is returned and the caller errors out.
func resolveGitHubToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("GITHUB_TOKEN")
}

// errVerifyFailed signals "verify ran cleanly but the provider said no".
// main.go can map this to a non-zero exit code without conflating it
// with a transport / config error.
var errVerifyFailed = errors.New("verify failed")

// IsVerifyError reports whether err is the verify-failed sentinel.
// Mirrors IsFindingsError so main.go has one shape to dispatch on.
func IsVerifyError(err error) bool { return err == errVerifyFailed }

// cmdContext returns cmd's context, falling back to context.Background()
// when cobra hasn't installed one (notably during unit tests that build
// commands directly without running them through ExecuteContext).
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
