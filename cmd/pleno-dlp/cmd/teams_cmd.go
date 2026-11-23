package cmd

import (
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type teamsFlags struct {
	token   string
	teamIDs []string
	baseURL string
}

var (
	scanTeamsOpts   teamsFlags
	verifyTeamsOpts teamsFlags
)

var scanTeamsCmd = &cobra.Command{
	Use:   "teams",
	Short: "Scan Microsoft Teams channel messages and replies for secrets",
	Long: "Scan Microsoft Teams channel messages and their replies via Microsoft Graph.\n" +
		"Reads --token, falling back to MS_GRAPH_TOKEN (needs ChannelMessage.Read.All).\n" +
		"Without --team, every team from /me/joinedTeams is scanned (delegated token).\n" +
		"With --incremental, messages whose lastModifiedDateTime is unchanged are skipped.",
	Args: cobra.NoArgs,
	RunE: runScanTeams,
}

var verifyTeamsCmd = &cobra.Command{
	Use:   "teams",
	Short: "Verify a Microsoft Graph access token",
	Args:  cobra.NoArgs,
	RunE:  runVerifyTeams,
}

func init() {
	scanTeamsCmd.Flags().StringVar(&scanTeamsOpts.token, "token", "", "Microsoft Graph access token (falls back to MS_GRAPH_TOKEN)")
	scanTeamsCmd.Flags().StringSliceVar(&scanTeamsOpts.teamIDs, "team", nil, "team ID(s) to scan (default: all joined teams)")
	scanTeamsCmd.Flags().StringVar(&scanTeamsOpts.baseURL, "base-url", "", "Graph API base URL (default https://graph.microsoft.com/v1.0)")
	scanCmd.AddCommand(scanTeamsCmd)

	verifyTeamsCmd.Flags().StringVar(&verifyTeamsOpts.token, "token", "", "Microsoft Graph access token (falls back to MS_GRAPH_TOKEN)")
	verifyTeamsCmd.Flags().StringVar(&verifyTeamsOpts.baseURL, "base-url", "", "Graph API base URL (default https://graph.microsoft.com/v1.0)")
	verifyCmd.AddCommand(verifyTeamsCmd)
}

func runScanTeams(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(scanTeamsOpts.token, "MS_GRAPH_TOKEN")
	if token == "" {
		return errors.New("teams: --token is required (or set MS_GRAPH_TOKEN)")
	}
	return runScanSaaS(cmd, "teams", connectors.Config{
		"token":    token,
		"team_ids": strings.Join(scanTeamsOpts.teamIDs, ","),
		"base_url": scanTeamsOpts.baseURL,
	})
}

func runVerifyTeams(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(verifyTeamsOpts.token, "MS_GRAPH_TOKEN")
	if token == "" {
		return errors.New("teams: --token is required (or set MS_GRAPH_TOKEN)")
	}
	return runVerifySaaS(cmd, "teams", token, connectors.Config{"base_url": verifyTeamsOpts.baseURL})
}
