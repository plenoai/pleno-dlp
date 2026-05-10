package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type confluenceFlags struct {
	site    string
	email   string
	token   string
	space   string
	apiBase string
}

var (
	scanConfluenceOpts   confluenceFlags
	verifyConfluenceOpts confluenceFlags
)

var scanConfluenceCmd = &cobra.Command{
	Use:   "confluence",
	Short: "Scan Confluence pages and comments for secrets (Cloud and Data Center)",
	Long: "Scan Confluence pages and comments for secrets. Uses --token, falling back to the CONFLUENCE_TOKEN env var.\n" +
		"For Cloud, provide --site and --email. For Data Center, use --api-base and omit --email.\n" +
		"Optionally filter with --space.",
	Args: cobra.NoArgs,
	RunE: runScanConfluence,
}

var verifyConfluenceCmd = &cobra.Command{
	Use:   "confluence",
	Short: "Verify a Confluence token (calls GET /rest/api/user/current)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyConfluence,
}

func init() {
	scanConfluenceCmd.Flags().StringVar(&scanConfluenceOpts.site, "site", "", "Atlassian Cloud site name (e.g. 'myorg' for myorg.atlassian.net/wiki)")
	scanConfluenceCmd.Flags().StringVar(&scanConfluenceOpts.email, "email", "", "Atlassian account email (Cloud; falls back to CONFLUENCE_EMAIL env var)")
	scanConfluenceCmd.Flags().StringVar(&scanConfluenceOpts.token, "token", "", "Confluence API token or PAT (falls back to the CONFLUENCE_TOKEN env var)")
	scanConfluenceCmd.Flags().StringVar(&scanConfluenceOpts.space, "space", "", "Confluence space key (optional filter)")
	scanConfluenceCmd.Flags().StringVar(&scanConfluenceOpts.apiBase, "api-base", "", "Confluence API base URL (default https://<site>.atlassian.net/wiki; override for Data Center)")
	scanCmd.AddCommand(scanConfluenceCmd)

	verifyConfluenceCmd.Flags().StringVar(&verifyConfluenceOpts.site, "site", "", "Atlassian Cloud site name")
	verifyConfluenceCmd.Flags().StringVar(&verifyConfluenceOpts.email, "email", "", "Atlassian account email (Cloud; falls back to CONFLUENCE_EMAIL env var)")
	verifyConfluenceCmd.Flags().StringVar(&verifyConfluenceOpts.token, "token", "", "Confluence API token or PAT (falls back to the CONFLUENCE_TOKEN env var)")
	verifyConfluenceCmd.Flags().StringVar(&verifyConfluenceOpts.apiBase, "api-base", "", "Confluence API base URL (override for Data Center)")
	verifyCmd.AddCommand(verifyConfluenceCmd)
}

func runScanConfluence(cmd *cobra.Command, _ []string) error {
	token := resolveConfluenceToken(scanConfluenceOpts.token)
	if token == "" {
		return errors.New("confluence: --token is required (or set the CONFLUENCE_TOKEN env var)")
	}
	apiBase := scanConfluenceOpts.apiBase
	if apiBase == "" && scanConfluenceOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net/wiki", scanConfluenceOpts.site)
	}
	if apiBase == "" {
		return errors.New("confluence: --site or --api-base is required")
	}
	return runScanSaaS(cmd, "confluence", connectors.Config{
		"token":    token,
		"email":    resolveConfluenceEmail(scanConfluenceOpts.email),
		"space":    scanConfluenceOpts.space,
		"api_base": apiBase,
	})
}

func runVerifyConfluence(cmd *cobra.Command, _ []string) error {
	token := resolveConfluenceToken(verifyConfluenceOpts.token)
	if token == "" {
		return errors.New("confluence: --token is required (or set the CONFLUENCE_TOKEN env var)")
	}
	apiBase := verifyConfluenceOpts.apiBase
	if apiBase == "" && verifyConfluenceOpts.site != "" {
		apiBase = fmt.Sprintf("https://%s.atlassian.net/wiki", verifyConfluenceOpts.site)
	}
	if apiBase == "" {
		return errors.New("confluence: --site or --api-base is required")
	}
	return runVerifySaaS(cmd, "confluence", token, connectors.Config{
		"api_base": apiBase,
		"email":    resolveConfluenceEmail(verifyConfluenceOpts.email),
	})
}

func resolveConfluenceToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("CONFLUENCE_TOKEN")
}

func resolveConfluenceEmail(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("CONFLUENCE_EMAIL")
}
