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

// jiraFlags collects the subset of Jira Config that surfaces as CLI flags.
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

// scanJiraCmd: `pleno-dlp scan jira --site <site> --email <email> --token <token>`.
var scanJiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Scan Jira issues for secrets (Cloud and Data Center)",
	Long: "Scan Jira issues for secrets. Uses --token, falling back to the JIRA_TOKEN env var.\n" +
		"For Cloud, provide --site and --email. For Data Center, use --api-base and omit --email.\n" +
		"Optionally filter with --project or --jql.",
	Args: cobra.NoArgs,
	RunE: runScanJira,
}

// verifyJiraCmd: `pleno-dlp verify jira [--token ... | $JIRA_TOKEN]`.
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

// runScanJira translates flags + env into a Config JSON blob and hands
// the rest to runScanCommon.
func runScanJira(cmd *cobra.Command, _ []string) error {
	token := resolveJiraToken(scanJiraOpts.token)
	if token == "" {
		return errors.New("jira: --token is required (or set the JIRA_TOKEN env var)")
	}
	email := resolveJiraEmail(scanJiraOpts.email)
	apiBase := scanJiraOpts.apiBase
	if apiBase == "" && scanJiraOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net", scanJiraOpts.site)
	}
	if apiBase == "" {
		return errors.New("jira: --site or --api-base is required")
	}
	src := sources.New(sources.SourceJira)
	if src == nil {
		return errors.New("jira source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"token":    token,
		"email":    email,
		"project":  scanJiraOpts.project,
		"jql":      scanJiraOpts.jql,
		"api_base": apiBase,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "jira")
}

// runVerifyJira builds the connector via the registry and dispatches the
// configured token to the connector's Verify method.
func runVerifyJira(cmd *cobra.Command, _ []string) error {
	token := resolveJiraToken(verifyJiraOpts.token)
	if token == "" {
		return errors.New("jira: --token is required (or set the JIRA_TOKEN env var)")
	}
	email := resolveJiraEmail(verifyJiraOpts.email)
	apiBase := verifyJiraOpts.apiBase
	if apiBase == "" && verifyJiraOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net", verifyJiraOpts.site)
	}
	if apiBase == "" {
		return errors.New("jira: --site or --api-base is required")
	}
	c := connectors.New("jira")
	if c == nil {
		return errors.New("jira connector is not registered (missing pkg/sources/all import?)")
	}
	if !c.Descriptor().Capabilities.Has(connectors.CapVerify) {
		return errors.New("jira connector does not advertise CapVerify (registry / capability mismatch)")
	}
	// Set api_base and email for verify context.
	if setter, ok := c.(interface{ SetAPIBase(string) }); ok {
		setter.SetAPIBase(apiBase)
	}
	// Inject email into config for Basic auth.
	type emailSetter interface{ SetEmail(string) }
	if es, ok := c.(emailSetter); ok && email != "" {
		es.SetEmail(email)
	}
	v, ok := c.(connectors.Verifier)
	if !ok {
		return errors.New("jira connector does not implement Verifier despite CapVerify (registry drift)")
	}
	verified, err := v.Verify(cmdContext(cmd), token)
	if err != nil {
		return fmt.Errorf("jira: verify: %w", err)
	}
	if !verified {
		fmt.Fprintln(cmd.OutOrStdout(), "jira: token NOT verified (401 / 403)")
		return errVerifyFailed
	}
	fmt.Fprintln(cmd.OutOrStdout(), "jira: token verified")
	return nil
}

// resolveJiraToken implements the documented fallback: explicit --token
// wins; otherwise JIRA_TOKEN env var.
func resolveJiraToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("JIRA_TOKEN")
}

// resolveJiraEmail implements the documented fallback: explicit --email
// wins; otherwise JIRA_EMAIL env var.
func resolveJiraEmail(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("JIRA_EMAIL")
}
