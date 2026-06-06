package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type gitlabFlags struct {
	group           string
	project         string
	token           string
	apiBase         string
	includeComments bool
}

var (
	scanGitLabOpts   gitlabFlags
	verifyGitLabOpts gitlabFlags
)

var scanGitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Scan a GitLab group or single project (default-branch blobs)",
	Long: "Scan a GitLab group or single project. Reads --token, falling back to the GITLAB_TOKEN env var.\n" +
		"--group and --project are mutually exclusive; one is required. Use --api-base for self-hosted GitLab.",
	Args: cobra.NoArgs,
	RunE: runScanGitLab,
}

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
	scanGitLabCmd.Flags().BoolVar(&scanGitLabOpts.includeComments, "include-comments", false, "also scan merge request notes and discussion notes")
	scanCmd.AddCommand(scanGitLabCmd)

	verifyGitLabCmd.Flags().StringVar(&verifyGitLabOpts.token, "token", "", "GitLab PAT or OAuth token (falls back to the GITLAB_TOKEN env var)")
	verifyGitLabCmd.Flags().StringVar(&verifyGitLabOpts.apiBase, "api-base", "", "GitLab API base URL (default https://gitlab.com/api/v4; override for self-hosted)")
	verifyCmd.AddCommand(verifyGitLabCmd)
}

func runScanGitLab(cmd *cobra.Command, _ []string) error {
	if scanGitLabOpts.group == "" && scanGitLabOpts.project == "" {
		return errors.New("gitlab: one of --group or --project is required")
	}
	token := resolveGitLabToken(scanGitLabOpts.token)
	if token == "" {
		return errors.New("gitlab: --token is required (or set the GITLAB_TOKEN env var)")
	}
	return runScanSaaS(cmd, "gitlab", connectors.Config{
		"token":            token,
		"group":            scanGitLabOpts.group,
		"project":          scanGitLabOpts.project,
		"api_base":         scanGitLabOpts.apiBase,
		"include_comments": fmt.Sprintf("%t", scanGitLabOpts.includeComments),
	})
}

func runVerifyGitLab(cmd *cobra.Command, _ []string) error {
	token := resolveGitLabToken(verifyGitLabOpts.token)
	if token == "" {
		return errors.New("gitlab: --token is required (or set the GITLAB_TOKEN env var)")
	}
	return runVerifySaaS(cmd, "gitlab", token, connectors.Config{"api_base": verifyGitLabOpts.apiBase})
}

func resolveGitLabToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("GITLAB_TOKEN")
}
