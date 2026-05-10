package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type bitbucketFlags struct {
	workspace   string
	repo        string
	username    string
	appPassword string
	token       string
	apiBase     string
}

var (
	scanBitbucketOpts   bitbucketFlags
	verifyBitbucketOpts bitbucketFlags
)

var scanBitbucketCmd = &cobra.Command{
	Use:   "bitbucket",
	Short: "Scan a Bitbucket workspace or single repo (default-branch files)",
	Long: "Scan a Bitbucket workspace or single repo. Reads --token or --app-password, " +
		"falling back to the BITBUCKET_APP_PASSWORD env var.\n" +
		"--workspace and --repo are mutually exclusive; one is required. Use --api-base for self-hosted Bitbucket.",
	Args: cobra.NoArgs,
	RunE: runScanBitbucket,
}

var verifyBitbucketCmd = &cobra.Command{
	Use:   "bitbucket",
	Short: "Verify a Bitbucket token (calls GET /2.0/user)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyBitbucket,
}

func init() {
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.workspace, "workspace", "", "Bitbucket workspace slug to scan (mutually exclusive with --repo)")
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.repo, "repo", "", "single Bitbucket repository in workspace/slug form (mutually exclusive with --workspace)")
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.username, "username", "", "Bitbucket username for app-password auth (required with --app-password)")
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.appPassword, "app-password", "", "Bitbucket app password (falls back to the BITBUCKET_APP_PASSWORD env var)")
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.token, "token", "", "Bitbucket workspace/repository access token (Bearer auth; mutually exclusive with --app-password)")
	scanBitbucketCmd.Flags().StringVar(&scanBitbucketOpts.apiBase, "api-base", "", "Bitbucket API base URL (default https://api.bitbucket.org/2.0)")
	scanCmd.AddCommand(scanBitbucketCmd)

	verifyBitbucketCmd.Flags().StringVar(&verifyBitbucketOpts.token, "token", "", "Bitbucket access token")
	verifyBitbucketCmd.Flags().StringVar(&verifyBitbucketOpts.apiBase, "api-base", "", "Bitbucket API base URL (default https://api.bitbucket.org/2.0)")
	verifyCmd.AddCommand(verifyBitbucketCmd)
}

func runScanBitbucket(cmd *cobra.Command, _ []string) error {
	if scanBitbucketOpts.workspace == "" && scanBitbucketOpts.repo == "" {
		return errors.New("bitbucket: one of --workspace or --repo is required")
	}
	token, appPassword := resolveBitbucketAuth(scanBitbucketOpts.token, scanBitbucketOpts.appPassword)
	if token == "" && appPassword == "" {
		return errors.New("bitbucket: --token or --app-password is required (or set the BITBUCKET_APP_PASSWORD env var)")
	}
	if token != "" && appPassword != "" {
		return errors.New("bitbucket: --token and --app-password are mutually exclusive")
	}
	if appPassword != "" && scanBitbucketOpts.username == "" {
		return errors.New("bitbucket: --username is required when using --app-password")
	}
	return runScanSaaS(cmd, "bitbucket", connectors.Config{
		"token":        token,
		"username":     scanBitbucketOpts.username,
		"app_password": appPassword,
		"workspace":    scanBitbucketOpts.workspace,
		"repo":         scanBitbucketOpts.repo,
		"api_base":     scanBitbucketOpts.apiBase,
	})
}

func runVerifyBitbucket(cmd *cobra.Command, _ []string) error {
	token, _ := resolveBitbucketAuth(verifyBitbucketOpts.token, "")
	if token == "" {
		return errors.New("bitbucket: --token is required for verify")
	}
	return runVerifySaaS(cmd, "bitbucket", token, connectors.Config{"api_base": verifyBitbucketOpts.apiBase})
}

func resolveBitbucketAuth(explicitToken, explicitAppPassword string) (token, appPassword string) {
	if explicitToken != "" {
		return explicitToken, ""
	}
	if explicitAppPassword != "" {
		return "", explicitAppPassword
	}
	if pw := os.Getenv("BITBUCKET_APP_PASSWORD"); pw != "" {
		return "", pw
	}
	return "", ""
}
