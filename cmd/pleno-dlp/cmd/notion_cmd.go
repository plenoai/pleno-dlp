package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type notionFlags struct {
	token   string
	apiBase string
	query   string
}

var (
	scanNotionOpts   notionFlags
	verifyNotionOpts notionFlags
)

var scanNotionCmd = &cobra.Command{
	Use:   "notion",
	Short: "Scan a Notion workspace (pages and databases)",
	Long: "Scan a Notion workspace for secrets. Reads --token, falling back to the NOTION_TOKEN env var.\n" +
		"Uses --query to filter the workspace search (optional). Use --api-base for custom Notion instances.",
	Args: cobra.NoArgs,
	RunE: runScanNotion,
}

var verifyNotionCmd = &cobra.Command{
	Use:   "notion",
	Short: "Verify a Notion integration token (calls GET /users/me)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyNotion,
}

func init() {
	scanNotionCmd.Flags().StringVar(&scanNotionOpts.token, "token", "", "Notion integration token (falls back to the NOTION_TOKEN env var)")
	scanNotionCmd.Flags().StringVar(&scanNotionOpts.apiBase, "api-base", "", "Notion API base URL (default https://api.notion.com/v1)")
	scanNotionCmd.Flags().StringVar(&scanNotionOpts.query, "query", "", "optional search query to filter workspace results")
	scanCmd.AddCommand(scanNotionCmd)

	verifyNotionCmd.Flags().StringVar(&verifyNotionOpts.token, "token", "", "Notion integration token (falls back to the NOTION_TOKEN env var)")
	verifyNotionCmd.Flags().StringVar(&verifyNotionOpts.apiBase, "api-base", "", "Notion API base URL (default https://api.notion.com/v1)")
	verifyCmd.AddCommand(verifyNotionCmd)
}

func runScanNotion(cmd *cobra.Command, _ []string) error {
	token := resolveNotionToken(scanNotionOpts.token)
	if token == "" {
		return errors.New("notion: --token is required (or set the NOTION_TOKEN env var)")
	}
	return runScanSaaS(cmd, "notion", connectors.Config{
		"token":    token,
		"api_base": scanNotionOpts.apiBase,
		"query":    scanNotionOpts.query,
	})
}

func runVerifyNotion(cmd *cobra.Command, _ []string) error {
	token := resolveNotionToken(verifyNotionOpts.token)
	if token == "" {
		return errors.New("notion: --token is required (or set the NOTION_TOKEN env var)")
	}
	return runVerifySaaS(cmd, "notion", token, connectors.Config{"api_base": verifyNotionOpts.apiBase})
}

func resolveNotionToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("NOTION_TOKEN")
}
