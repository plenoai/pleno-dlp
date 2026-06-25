package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type circleciFlags struct {
	token      string
	baseURL    string
	maxPipelines int
}

var (
	scanCircleCIOpts   circleciFlags
	verifyCircleCIOpts circleciFlags
)

var scanCircleCICmd = &cobra.Command{
	Use:   "circleci",
	Short: "Scan all followed CircleCI projects (pipeline configs)",
	Long: "Enumerate all CircleCI projects the token can access and scan each project's\n" +
		"recent pipeline configs (config.yml) for secrets. Reads --token, falling back\n" +
		"to the CIRCLE_TOKEN env var.",
	Args: cobra.NoArgs,
	RunE: runScanCircleCI,
}

var verifyCircleCICmd = &cobra.Command{
	Use:   "circleci",
	Short: "Verify a CircleCI personal API token (calls GET /api/v2/me)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyCircleCI,
}

func init() {
	scanCircleCICmd.Flags().StringVar(&scanCircleCIOpts.token, "token", "", "CircleCI personal API token (falls back to the CIRCLE_TOKEN env var)")
	scanCircleCICmd.Flags().StringVar(&scanCircleCIOpts.baseURL, "base-url", "", "CircleCI base URL (default https://circleci.com)")
	scanCmd.AddCommand(scanCircleCICmd)

	verifyCircleCICmd.Flags().StringVar(&verifyCircleCIOpts.token, "token", "", "CircleCI personal API token (falls back to the CIRCLE_TOKEN env var)")
	verifyCircleCICmd.Flags().StringVar(&verifyCircleCIOpts.baseURL, "base-url", "", "CircleCI base URL (default https://circleci.com)")
	verifyCmd.AddCommand(verifyCircleCICmd)
}

func runScanCircleCI(cmd *cobra.Command, _ []string) error {
	token := resolveCircleCIToken(scanCircleCIOpts.token)
	if token == "" {
		return errors.New("circleci: --token is required (or set the CIRCLE_TOKEN env var)")
	}
	cfg := connectors.Config{
		"token":    token,
		"base_url": scanCircleCIOpts.baseURL,
	}
	return runScanSaaS(cmd, "circleci", cfg)
}

func runVerifyCircleCI(cmd *cobra.Command, _ []string) error {
	token := resolveCircleCIToken(verifyCircleCIOpts.token)
	if token == "" {
		return errors.New("circleci: --token is required (or set the CIRCLE_TOKEN env var)")
	}
	return runVerifySaaS(cmd, "circleci", token, connectors.Config{
		"base_url": verifyCircleCIOpts.baseURL,
	})
}

func resolveCircleCIToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("CIRCLE_TOKEN")
}
