package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type splunkFlags struct {
	token    string
	host     string
	query    string
	earliest string
	latest   string
}

var (
	scanSplunkOpts   splunkFlags
	verifySplunkOpts splunkFlags
)

var scanSplunkCmd = &cobra.Command{
	Use:   "splunk",
	Short: "Scan Splunk search results for secrets",
	Long: "Scan Splunk search results for secrets via the REST search API.\n" +
		"Reads --token, falling back to SPLUNK_TOKEN env var.\n" +
		"--host is required (e.g. https://splunk.example.com:8089).\n" +
		"--query sets the SPL search (default \"search index=* | head 1000\").",
	Args: cobra.NoArgs,
	RunE: runScanSplunk,
}

var verifySplunkCmd = &cobra.Command{
	Use:   "splunk",
	Short: "Verify a Splunk token",
	Args:  cobra.NoArgs,
	RunE:  runVerifySplunk,
}

func init() {
	scanSplunkCmd.Flags().StringVar(&scanSplunkOpts.token, "token", "", "Splunk Bearer token (falls back to SPLUNK_TOKEN)")
	scanSplunkCmd.Flags().StringVar(&scanSplunkOpts.host, "host", "", "Splunk host URL (e.g. https://splunk.example.com:8089)")
	scanSplunkCmd.Flags().StringVar(&scanSplunkOpts.query, "query", "", "SPL search query (default \"search index=* | head 1000\")")
	scanSplunkCmd.Flags().StringVar(&scanSplunkOpts.earliest, "earliest", "", "Earliest time (default \"-24h\")")
	scanSplunkCmd.Flags().StringVar(&scanSplunkOpts.latest, "latest", "", "Latest time (default \"now\")")
	scanCmd.AddCommand(scanSplunkCmd)

	verifySplunkCmd.Flags().StringVar(&verifySplunkOpts.token, "token", "", "Splunk Bearer token (falls back to SPLUNK_TOKEN)")
	verifySplunkCmd.Flags().StringVar(&verifySplunkOpts.host, "host", "", "Splunk host URL")
	verifyCmd.AddCommand(verifySplunkCmd)
}

func runScanSplunk(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(scanSplunkOpts.token, "SPLUNK_TOKEN")
	if token == "" {
		return errors.New("splunk: --token is required (or set SPLUNK_TOKEN)")
	}
	if scanSplunkOpts.host == "" {
		return errors.New("splunk: --host is required")
	}
	return runScanSaaS(cmd, "splunk", connectors.Config{
		"token":    token,
		"host":     scanSplunkOpts.host,
		"query":    scanSplunkOpts.query,
		"earliest": scanSplunkOpts.earliest,
		"latest":   scanSplunkOpts.latest,
	})
}

func runVerifySplunk(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(verifySplunkOpts.token, "SPLUNK_TOKEN")
	if token == "" {
		return errors.New("splunk: --token is required (or set SPLUNK_TOKEN)")
	}
	if verifySplunkOpts.host == "" {
		return errors.New("splunk: --host is required")
	}
	return runVerifySaaS(cmd, "splunk", token, connectors.Config{"host": verifySplunkOpts.host})
}
