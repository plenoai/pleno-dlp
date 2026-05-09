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

// slackFlags collects the subset of Slack Config that surfaces as CLI flags.
type slackFlags struct {
	token   string
	channel string
	apiBase string
}

var (
	scanSlackOpts   slackFlags
	verifySlackOpts slackFlags
)

// scanSlackCmd: `pleno-dlp scan slack --token <token> [--channel <id>]`.
var scanSlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scan a Slack workspace for secrets",
	Long: "Scan a Slack workspace for secrets. Reads --token, falling back to the SLACK_TOKEN env var.\n" +
		"--channel scopes the scan to a single channel by ID; omit to scan every channel the token can see.",
	Args: cobra.NoArgs,
	RunE: runScanSlack,
}

// verifySlackCmd: `pleno-dlp verify slack [--token ... | $SLACK_TOKEN]`.
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

// runScanSlack translates flags + SLACK_TOKEN into a Config JSON blob and
// hands the rest to runScanCommon.
func runScanSlack(cmd *cobra.Command, _ []string) error {
	token := resolveSlackToken(scanSlackOpts.token)
	if token == "" {
		return errors.New("slack: --token is required (or set the SLACK_TOKEN env var)")
	}
	src := sources.New(sources.SourceSlack)
	if src == nil {
		return errors.New("slack source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"token":   token,
		"channel": scanSlackOpts.channel,
		"api_base": scanSlackOpts.apiBase,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "slack")
}

// runVerifySlack builds the connector via the registry and dispatches the
// configured token to the connector's Verify method.
func runVerifySlack(cmd *cobra.Command, _ []string) error {
	token := resolveSlackToken(verifySlackOpts.token)
	if token == "" {
		return errors.New("slack: --token is required (or set the SLACK_TOKEN env var)")
	}
	c := connectors.New("slack")
	if c == nil {
		return errors.New("slack connector is not registered (missing pkg/sources/all import?)")
	}
	if !c.Descriptor().Capabilities.Has(connectors.CapVerify) {
		return errors.New("slack connector does not advertise CapVerify (registry / capability mismatch)")
	}
	if setter, ok := c.(interface{ SetAPIBase(string) }); ok && verifySlackOpts.apiBase != "" {
		setter.SetAPIBase(verifySlackOpts.apiBase)
	}
	v, ok := c.(connectors.Verifier)
	if !ok {
		return errors.New("slack connector does not implement Verifier despite CapVerify (registry drift)")
	}
	verified, err := v.Verify(cmdContext(cmd), token)
	if err != nil {
		return fmt.Errorf("slack: verify: %w", err)
	}
	if !verified {
		fmt.Fprintln(cmd.OutOrStdout(), "slack: token NOT verified")
		return errVerifyFailed
	}
	fmt.Fprintln(cmd.OutOrStdout(), "slack: token verified")
	return nil
}

// resolveSlackToken implements the documented fallback: explicit --token
// flag wins; otherwise the SLACK_TOKEN env var is consulted; otherwise
// the empty string is returned and the caller errors out.
func resolveSlackToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("SLACK_TOKEN")
}
