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

// notionFlags collects the subset of Notion Config that surfaces as CLI
// flags.
type notionFlags struct {
	token   string
	apiBase string
	query   string
}

var (
	scanNotionOpts   notionFlags
	verifyNotionOpts notionFlags
)

// scanNotionCmd: `pleno-dlp scan notion --token <token>`.
var scanNotionCmd = &cobra.Command{
	Use:   "notion",
	Short: "Scan a Notion workspace (pages and databases)",
	Long: "Scan a Notion workspace for secrets. Reads --token, falling back to the NOTION_TOKEN env var.\n" +
		"Uses --query to filter the workspace search (optional). Use --api-base for custom Notion instances.",
	Args: cobra.NoArgs,
	RunE: runScanNotion,
}

// verifyNotionCmd: `pleno-dlp verify notion [--token ... | $NOTION_TOKEN]`.
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

// runScanNotion translates flags + NOTION_TOKEN into a Config JSON blob
// and hands the rest to runScanCommon.
func runScanNotion(cmd *cobra.Command, _ []string) error {
	token := resolveNotionToken(scanNotionOpts.token)
	if token == "" {
		return errors.New("notion: --token is required (or set the NOTION_TOKEN env var)")
	}
	src := sources.New(sources.SourceNotion)
	if src == nil {
		return errors.New("notion source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"token":    token,
		"api_base": scanNotionOpts.apiBase,
		"query":    scanNotionOpts.query,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "notion")
}

// runVerifyNotion builds the connector via the registry and dispatches
// the configured token to the connector's Verify method.
func runVerifyNotion(cmd *cobra.Command, _ []string) error {
	token := resolveNotionToken(verifyNotionOpts.token)
	if token == "" {
		return errors.New("notion: --token is required (or set the NOTION_TOKEN env var)")
	}
	c := connectors.New("notion")
	if c == nil {
		return errors.New("notion connector is not registered (missing pkg/sources/all import?)")
	}
	if !c.Descriptor().Capabilities.Has(connectors.CapVerify) {
		return errors.New("notion connector does not advertise CapVerify (registry / capability mismatch)")
	}
	if setter, ok := c.(interface{ SetAPIBase(string) }); ok && verifyNotionOpts.apiBase != "" {
		setter.SetAPIBase(verifyNotionOpts.apiBase)
	}
	v, ok := c.(connectors.Verifier)
	if !ok {
		return errors.New("notion connector does not implement Verifier despite CapVerify (registry drift)")
	}
	verified, err := v.Verify(cmdContext(cmd), token)
	if err != nil {
		return fmt.Errorf("notion: verify: %w", err)
	}
	if !verified {
		fmt.Fprintln(cmd.OutOrStdout(), "notion: token NOT verified (401)")
		return errVerifyFailed
	}
	fmt.Fprintln(cmd.OutOrStdout(), "notion: token verified")
	return nil
}

// resolveNotionToken implements the documented fallback: explicit --token
// flag wins; otherwise the NOTION_TOKEN env var is consulted; otherwise
// the empty string is returned and the caller errors out.
func resolveNotionToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("NOTION_TOKEN")
}
