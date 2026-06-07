package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type redashFlags struct {
	apiKey   string
	host     string
	queryIDs string
}

var (
	scanRedashOpts   redashFlags
	verifyRedashOpts redashFlags
)

var scanRedashCmd = &cobra.Command{
	Use:   "redash",
	Short: "Scan Redash query results for secrets",
	Long: "Scan Redash query results for secrets via the REST API.\n" +
		"Reads --api-key, falling back to REDASH_API_KEY env var.\n" +
		"--host is required. --query-ids limits scan to specific queries.",
	Args: cobra.NoArgs,
	RunE: runScanRedash,
}

var verifyRedashCmd = &cobra.Command{
	Use:   "redash",
	Short: "Verify a Redash API key",
	Args:  cobra.NoArgs,
	RunE:  runVerifyRedash,
}

func init() {
	scanRedashCmd.Flags().StringVar(&scanRedashOpts.apiKey, "api-key", "", "Redash API key (falls back to REDASH_API_KEY)")
	scanRedashCmd.Flags().StringVar(&scanRedashOpts.host, "host", "", "Redash host URL (e.g. https://redash.example.com)")
	scanRedashCmd.Flags().StringVar(&scanRedashOpts.queryIDs, "query-ids", "", "Comma-separated query IDs to scan (omit to scan all)")
	scanCmd.AddCommand(scanRedashCmd)

	verifyRedashCmd.Flags().StringVar(&verifyRedashOpts.apiKey, "api-key", "", "Redash API key (falls back to REDASH_API_KEY)")
	verifyRedashCmd.Flags().StringVar(&verifyRedashOpts.host, "host", "", "Redash host URL")
	verifyCmd.AddCommand(verifyRedashCmd)
}

func runScanRedash(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(scanRedashOpts.apiKey, "REDASH_API_KEY")
	if apiKey == "" {
		return errors.New("redash: --api-key is required (or set REDASH_API_KEY)")
	}
	if scanRedashOpts.host == "" {
		return errors.New("redash: --host is required")
	}
	return runScanSaaS(cmd, "redash", connectors.Config{
		"api_key":   apiKey,
		"host":      scanRedashOpts.host,
		"query_ids": scanRedashOpts.queryIDs,
	})
}

func runVerifyRedash(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(verifyRedashOpts.apiKey, "REDASH_API_KEY")
	if apiKey == "" {
		return errors.New("redash: --api-key is required (or set REDASH_API_KEY)")
	}
	if verifyRedashOpts.host == "" {
		return errors.New("redash: --host is required")
	}
	return runVerifySaaS(cmd, "redash", apiKey, connectors.Config{"host": verifyRedashOpts.host})
}
