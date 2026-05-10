package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type jiraFlags struct {
	site    string
	email   string
	token   string
	project string
	jql     string
	apiBase string
}

var (
	scanJiraOpts   jiraFlags
	verifyJiraOpts jiraFlags
)

var scanJiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Scan Jira issues for secrets (Cloud and Data Center)",
	Long: "Scan Jira issues for secrets. Uses --token, falling back to the JIRA_TOKEN env var.\n" +
		"For Cloud, provide --site and --email. For Data Center, use --api-base and omit --email.\n" +
		"Optionally filter with --project or --jql.",
	Args: cobra.NoArgs,
	RunE: runScanJira,
}

var verifyJiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Verify a Jira token (calls GET /rest/api/3/myself)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyJira,
}

func init() {
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.site, "site", "", "Atlassian Cloud site name (e.g. 'myorg' for myorg.atlassian.net)")
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.email, "email", "", "Atlassian account email (required for Cloud; falls back to JIRA_EMAIL env var)")
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.token, "token", "", "Jira API token or PAT (falls back to the JIRA_TOKEN env var)")
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.project, "project", "", "Jira project key to scan (e.g. PROJ)")
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.jql, "jql", "", "raw JQL query (overrides --project)")
	scanJiraCmd.Flags().StringVar(&scanJiraOpts.apiBase, "api-base", "", "Jira API base URL (default https://<site>.atlassian.net; override for Data Center)")
	scanCmd.AddCommand(scanJiraCmd)

	verifyJiraCmd.Flags().StringVar(&verifyJiraOpts.site, "site", "", "Atlassian Cloud site name")
	verifyJiraCmd.Flags().StringVar(&verifyJiraOpts.email, "email", "", "Atlassian account email (Cloud; falls back to JIRA_EMAIL env var)")
	verifyJiraCmd.Flags().StringVar(&verifyJiraOpts.token, "token", "", "Jira API token or PAT (falls back to the JIRA_TOKEN env var)")
	verifyJiraCmd.Flags().StringVar(&verifyJiraOpts.apiBase, "api-base", "", "Jira API base URL (override for Data Center)")
	verifyCmd.AddCommand(verifyJiraCmd)
}

func runScanJira(cmd *cobra.Command, _ []string) error {
	token := resolveJiraToken(scanJiraOpts.token)
	if token == "" {
		return errors.New("jira: --token is required (or set the JIRA_TOKEN env var)")
	}
	apiBase := scanJiraOpts.apiBase
	if apiBase == "" && scanJiraOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net", scanJiraOpts.site)
	}
	if apiBase == "" {
		return errors.New("jira: --site or --api-base is required")
	}
	return runScanSaaS(cmd, "jira", connectors.Config{
		"token":    token,
		"email":    resolveJiraEmail(scanJiraOpts.email),
		"project":  scanJiraOpts.project,
		"jql":      scanJiraOpts.jql,
		"api_base": apiBase,
	})
}

func runVerifyJira(cmd *cobra.Command, _ []string) error {
	token := resolveJiraToken(verifyJiraOpts.token)
	if token == "" {
		return errors.New("jira: --token is required (or set the JIRA_TOKEN env var)")
	}
	apiBase := verifyJiraOpts.apiBase
	if apiBase == "" && verifyJiraOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net", verifyJiraOpts.site)
	}
	if apiBase == "" {
		return errors.New("jira: --site or --api-base is required")
	}
	return runVerifySaaS(cmd, "jira", token, connectors.Config{
		"api_base": apiBase,
		"email":    resolveJiraEmail(verifyJiraOpts.email),
	})
}

func resolveJiraToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("JIRA_TOKEN")
}

func resolveJiraEmail(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("JIRA_EMAIL")
}
