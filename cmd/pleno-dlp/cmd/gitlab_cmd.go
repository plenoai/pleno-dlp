package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// gitlabFlags collects the subset of GitLab Config that surfaces as CLI flags.
type gitlabFlags struct {
	group   string
	project string
	token   string
	apiBase string
}

var (
	scanGitLabOpts   gitlabFlags
	verifyGitLabOpts gitlabFlags
)

// scanGitLabCmd: pleno-dlp scan gitlab --group acme [--api-base ...].
var scanGitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Scan a GitLab group or single project (default-branch blobs)",
	Long: "Scan a GitLab group or single project. Reads --token, falling back to the GITLAB_TOKEN env var.\n" +
		"--group and --project are mutually exclusive; one is required. Use --api-base for self-hosted GitLab.",
	Args: cobra.NoArgs,
	RunE: runScanGitLab,
}

// verifyGitLabCmd: pleno-dlp verify gitlab [--token ... | $GITLAB_TOKEN].
var verifyGitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Verify a GitLab token (calls GET /user)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyGitLab,
}

func init() {
	scanGitLabCmd.Flags().StringVar(&scanGitLabOpts.group, "group", "", "GitLab group path to scan (mutually exclusive with --project)")
	scanGitLabCmd.Flags().StringVar(&scanGitLabOpts.project, "project", "", "single GitLab project in namespace/name form (mutually exclusive with --group)")
	scanGitLabCmd.Flags().StringVar(&scanGitLabOpts.token, "token", "", "GitLab PAT or OAuth token (falls back to the GITLAB_TOKEN env var)")
	scanGitLabCmd.Flags().StringVar(&scanGitLabOpts.apiBase, "api-base", "", "GitLab API base URL (default https://gitlab.com/api/v4; override for self-hosted)")
	scanCmd.AddCommand(scanGitLabCmd)

	verifyGitLabCmd.Flags().StringVar(&verifyGitLabOpts.token, "token", "", "GitLab PAT or OAuth token (falls back to the GITLAB_TOKEN env var)")
	verifyGitLabCmd.Flags().StringVar(&verifyGitLabOpts.apiBase, "api-base", "", "GitLab API base URL (default https://gitlab.com/api/v4; override for self-hosted)")
	verifyCmd.AddCommand(verifyGitLabCmd)
}

// runScanGitLab translates flags + GITLAB_TOKEN into a Config JSON blob
// and hands the rest to runScanCommon.
func runScanGitLab(cmd *cobra.Command, _ []string) error {
	if scanGitLabOpts.group == "" && scanGitLabOpts.project == "" {
		return errors.New("gitlab: one of --group or --project is required")
	}
	token := resolveGitLabToken(scanGitLabOpts.token)
	if token == "" {
		return errors.New("gitlab: --token is required (or set the GITLAB_TOKEN env var)")
	}
	src := sources.New(sources.SourceGitLab)
	if src == nil {
		return errors.New("gitlab source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"token":    token,
		"group":    scanGitLabOpts.group,
		"project":  scanGitLabOpts.project,
		"api_base": scanGitLabOpts.apiBase,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "gitlab")
}

// runVerifyGitLab builds the connector via the registry and dispatches the
// configured token to the connector's Verify method.
func runVerifyGitLab(cmd *cobra.Command, _ []string) error {
	token := resolveGitLabToken(verifyGitLabOpts.token)
	if token == "" {
		return errors.New("gitlab: --token is required (or set the GITLAB_TOKEN env var)")
	}
	c := connectors.New("gitlab")
	if c == nil {
		return errors.New("gitlab connector is not registered (missing pkg/sources/all import?)")
	}
	if !c.Descriptor().Capabilities.Has(connectors.CapVerify) {
		return errors.New("gitlab connector does not advertise CapVerify (registry / capability mismatch)")
	}
	if setter, ok := c.(interface{ SetAPIBase(string) }); ok && verifyGitLabOpts.apiBase != "" {
		setter.SetAPIBase(verifyGitLabOpts.apiBase)
	}
	v, ok := c.(connectors.Verifier)
	if !ok {
		return errors.New("gitlab connector does not implement Verifier despite CapVerify (registry drift)")
	}
	verified, err := v.Verify(cmdContext(cmd), token)
	if err != nil {
		return fmt.Errorf("gitlab: verify: %w", err)
	}
	if !verified {
		fmt.Fprintln(cmd.OutOrStdout(), "gitlab: token NOT verified (401 / 403)")
		return errVerifyFailed
	}
	fmt.Fprintln(cmd.OutOrStdout(), "gitlab: token verified")
	return nil
}

// resolveGitLabToken implements the documented fallback: explicit --token
// flag wins; otherwise the GITLAB_TOKEN env var is consulted; otherwise
// the empty string is returned and the caller errors out.
func resolveGitLabToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("GITLAB_TOKEN")
}
