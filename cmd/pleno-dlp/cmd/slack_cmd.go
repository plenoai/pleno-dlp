package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type slackFlags struct {
	token   string
	channel string
	apiBase string
}

var (
	scanSlackOpts   slackFlags
	verifySlackOpts slackFlags
)

var scanSlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scan a Slack workspace for secrets",
	Long: "Scan a Slack workspace for secrets. Reads --token, falling back to the SLACK_TOKEN env var.\n" +
		"--channel scopes the scan to a single channel by ID; omit to scan every channel the token can see.",
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
	return runScanSaaS(cmd, "slack", connectors.Config{
		"token":    token,
		"channel":  scanSlackOpts.channel,
		"api_base": scanSlackOpts.apiBase,
	})
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
