package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type bigqueryFlags struct {
	token   string
	project string
	query   string
	apiBase string
}

var (
	scanBigQueryOpts   bigqueryFlags
	verifyBigQueryOpts bigqueryFlags
)

var scanBigQueryCmd = &cobra.Command{
	Use:   "bigquery",
	Short: "Scan BigQuery query results for secrets",
	Long: "Scan BigQuery query results for secrets via the REST API.\n" +
		"Reads --token, falling back to BIGQUERY_TOKEN env var.\n" +
		"--project and --query are required.",
	Args: cobra.NoArgs,
	RunE: runScanBigQuery,
}

var verifyBigQueryCmd = &cobra.Command{
	Use:   "bigquery",
	Short: "Verify a BigQuery OAuth2 token",
	Args:  cobra.NoArgs,
	RunE:  runVerifyBigQuery,
}

func init() {
	scanBigQueryCmd.Flags().StringVar(&scanBigQueryOpts.token, "token", "", "OAuth2 Bearer token (falls back to BIGQUERY_TOKEN)")
	scanBigQueryCmd.Flags().StringVar(&scanBigQueryOpts.project, "project", "", "GCP project ID (required)")
	scanBigQueryCmd.Flags().StringVar(&scanBigQueryOpts.query, "query", "", "SQL query to execute (required)")
	scanBigQueryCmd.Flags().StringVar(&scanBigQueryOpts.apiBase, "api-base", "", "BigQuery API base URL (default https://bigquery.googleapis.com)")
	scanCmd.AddCommand(scanBigQueryCmd)

	verifyBigQueryCmd.Flags().StringVar(&verifyBigQueryOpts.token, "token", "", "OAuth2 Bearer token (falls back to BIGQUERY_TOKEN)")
	verifyBigQueryCmd.Flags().StringVar(&verifyBigQueryOpts.project, "project", "", "GCP project ID (required)")
	verifyBigQueryCmd.Flags().StringVar(&verifyBigQueryOpts.apiBase, "api-base", "", "BigQuery API base URL")
	verifyCmd.AddCommand(verifyBigQueryCmd)
}

func runScanBigQuery(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(scanBigQueryOpts.token, "BIGQUERY_TOKEN")
	if token == "" {
		return errors.New("bigquery: --token is required (or set BIGQUERY_TOKEN)")
	}
	if scanBigQueryOpts.project == "" {
		return errors.New("bigquery: --project is required")
	}
	if scanBigQueryOpts.query == "" {
		return errors.New("bigquery: --query is required")
	}
	return runScanSaaS(cmd, "bigquery", connectors.Config{
		"token":    token,
		"project":  scanBigQueryOpts.project,
		"query":    scanBigQueryOpts.query,
		"api_base": scanBigQueryOpts.apiBase,
	})
}

func runVerifyBigQuery(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(verifyBigQueryOpts.token, "BIGQUERY_TOKEN")
	if token == "" {
		return errors.New("bigquery: --token is required (or set BIGQUERY_TOKEN)")
	}
	if verifyBigQueryOpts.project == "" {
		return errors.New("bigquery: --project is required")
	}
	return runVerifySaaS(cmd, "bigquery", token, connectors.Config{
		"project":  verifyBigQueryOpts.project,
		"api_base": verifyBigQueryOpts.apiBase,
	})
}
