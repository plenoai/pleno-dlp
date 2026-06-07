package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type datadogFlags struct {
	apiKey string
	appKey string
	site   string
	query  string
	from   string
	to     string
}

var (
	scanDatadogOpts   datadogFlags
	verifyDatadogOpts datadogFlags
)

var scanDatadogCmd = &cobra.Command{
	Use:   "datadog",
	Short: "Scan Datadog logs for secrets",
	Long: "Scan Datadog logs for secrets via the Log Search API.\n" +
		"Reads --api-key and --app-key, falling back to DD_API_KEY and DD_APP_KEY env vars.\n" +
		"--query sets the log search filter (default \"*\").",
	Args: cobra.NoArgs,
	RunE: runScanDatadog,
}

var verifyDatadogCmd = &cobra.Command{
	Use:   "datadog",
	Short: "Verify a Datadog API key",
	Args:  cobra.NoArgs,
	RunE:  runVerifyDatadog,
}

func init() {
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.apiKey, "api-key", "", "Datadog API key (falls back to DD_API_KEY)")
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.appKey, "app-key", "", "Datadog Application key (falls back to DD_APP_KEY)")
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.site, "site", "", "Datadog API site URL (default https://api.datadoghq.com)")
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.query, "query", "", "Log search query (default \"*\")")
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.from, "from", "", "Start time in RFC 3339 (default 24h ago)")
	scanDatadogCmd.Flags().StringVar(&scanDatadogOpts.to, "to", "", "End time in RFC 3339 (default now)")
	scanCmd.AddCommand(scanDatadogCmd)

	verifyDatadogCmd.Flags().StringVar(&verifyDatadogOpts.apiKey, "api-key", "", "Datadog API key (falls back to DD_API_KEY)")
	verifyDatadogCmd.Flags().StringVar(&verifyDatadogOpts.site, "site", "", "Datadog API site URL (default https://api.datadoghq.com)")
	verifyCmd.AddCommand(verifyDatadogCmd)
}

func runScanDatadog(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(scanDatadogOpts.apiKey, "DD_API_KEY")
	if apiKey == "" {
		return errors.New("datadog: --api-key is required (or set DD_API_KEY)")
	}
	appKey := resolveEnv(scanDatadogOpts.appKey, "DD_APP_KEY")
	if appKey == "" {
		return errors.New("datadog: --app-key is required (or set DD_APP_KEY)")
	}
	return runScanSaaS(cmd, "datadog", connectors.Config{
		"api_key": apiKey,
		"app_key": appKey,
		"site":    scanDatadogOpts.site,
		"query":   scanDatadogOpts.query,
		"from":    scanDatadogOpts.from,
		"to":      scanDatadogOpts.to,
	})
}

func runVerifyDatadog(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(verifyDatadogOpts.apiKey, "DD_API_KEY")
	if apiKey == "" {
		return errors.New("datadog: --api-key is required (or set DD_API_KEY)")
	}
	return runVerifySaaS(cmd, "datadog", apiKey, connectors.Config{"site": verifyDatadogOpts.site})
}

func resolveEnv(explicit, envKey string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv(envKey)
}
