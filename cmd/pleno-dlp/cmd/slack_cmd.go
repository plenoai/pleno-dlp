package cmd

import (
	"errors"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type slackFlags struct {
	token      string
	channel    string
	apiBase    string
	query      string
	maxResults int
}

var (
	scanSlackOpts   slackFlags
	verifySlackOpts slackFlags
)

var scanSlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scan a Slack workspace for secrets",
	Long: "Scan a Slack workspace for secrets. Reads --token, falling back to the SLACK_TOKEN env var.\n" +
		"--channel scopes the scan to a single channel by ID; omit to scan every channel the token can see.\n" +
		"--query scans the messages and files matched by a Slack search query instead (user token with\n" +
		"search:read and files:read).",
	Args: cobra.NoArgs,
	RunE: runScanSlack,
}

var verifySlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Verify a Slack token (calls auth.test)",
	Args:  cobra.NoArgs,
	RunE:  runVerifySlack,
}

func init() {
	scanSlackCmd.Flags().StringVar(&scanSlackOpts.token, "token", "", "Slack Bot/User token (falls back to the SLACK_TOKEN env var)")
	scanSlackCmd.Flags().StringVar(&scanSlackOpts.channel, "channel", "", "single Slack channel ID to scan (omit to scan all accessible channels)")
	scanSlackCmd.Flags().StringVar(&scanSlackOpts.apiBase, "api-base", "", "Slack API base URL (default https://slack.com/api)")
	scanSlackCmd.Flags().StringVar(&scanSlackOpts.query, "query", "", "Slack search query; scan matching messages and files instead of walking channels (mutually exclusive with --channel)")
	scanSlackCmd.Flags().IntVar(&scanSlackOpts.maxResults, "max-results", 0, "with --query, cap message matches and file matches each (0 = all)")
	scanCmd.AddCommand(scanSlackCmd)

	verifySlackCmd.Flags().StringVar(&verifySlackOpts.token, "token", "", "Slack Bot/User token (falls back to the SLACK_TOKEN env var)")
	verifySlackCmd.Flags().StringVar(&verifySlackOpts.apiBase, "api-base", "", "Slack API base URL (default https://slack.com/api)")
	verifyCmd.AddCommand(verifySlackCmd)
}

func runScanSlack(cmd *cobra.Command, _ []string) error {
	token := resolveSlackToken(scanSlackOpts.token)
	if token == "" {
		return errors.New("slack: --token is required (or set the SLACK_TOKEN env var)")
	}
	cfg := connectors.Config{
		"token":    token,
		"channel":  scanSlackOpts.channel,
		"api_base": scanSlackOpts.apiBase,
	}
	if scanSlackOpts.query != "" {
		cfg["query"] = scanSlackOpts.query
	}
	if scanSlackOpts.maxResults < 0 {
		return errors.New("slack: --max-results must be non-negative")
	}
	if scanSlackOpts.maxResults > 0 {
		cfg["max_results"] = strconv.Itoa(scanSlackOpts.maxResults)
	}
	return runScanSaaS(cmd, "slack", cfg)
}

func runVerifySlack(cmd *cobra.Command, _ []string) error {
	token := resolveSlackToken(verifySlackOpts.token)
	if token == "" {
		return errors.New("slack: --token is required (or set the SLACK_TOKEN env var)")
	}
	return runVerifySaaS(cmd, "slack", token, connectors.Config{"api_base": verifySlackOpts.apiBase})
}

func resolveSlackToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("SLACK_TOKEN")
}
