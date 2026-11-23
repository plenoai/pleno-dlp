package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type postmanFlags struct {
	apiKey  string
	baseURL string
}

var (
	scanPostmanOpts   postmanFlags
	verifyPostmanOpts postmanFlags
)

var scanPostmanCmd = &cobra.Command{
	Use:   "postman",
	Short: "Scan Postman workspaces, collections, and environments for secrets",
	Long: "Scan every Postman workspace the API key can see: full collections (requests,\n" +
		"headers, bodies, variables, examples) and environments.\n" +
		"Reads --api-key, falling back to the POSTMAN_API_KEY env var.",
	Args: cobra.NoArgs,
	RunE: runScanPostman,
}

var verifyPostmanCmd = &cobra.Command{
	Use:   "postman",
	Short: "Verify a Postman API key",
	Args:  cobra.NoArgs,
	RunE:  runVerifyPostman,
}

func init() {
	scanPostmanCmd.Flags().StringVar(&scanPostmanOpts.apiKey, "api-key", "", "Postman API key (falls back to POSTMAN_API_KEY)")
	scanPostmanCmd.Flags().StringVar(&scanPostmanOpts.baseURL, "base-url", "", "Postman API base URL (default https://api.getpostman.com)")
	scanCmd.AddCommand(scanPostmanCmd)

	verifyPostmanCmd.Flags().StringVar(&verifyPostmanOpts.apiKey, "api-key", "", "Postman API key (falls back to POSTMAN_API_KEY)")
	verifyPostmanCmd.Flags().StringVar(&verifyPostmanOpts.baseURL, "base-url", "", "Postman API base URL (default https://api.getpostman.com)")
	verifyCmd.AddCommand(verifyPostmanCmd)
}

func postmanConfig(o postmanFlags) connectors.Config {
	cfg := connectors.Config{}
	if o.baseURL != "" {
		cfg["base_url"] = o.baseURL
	}
	return cfg
}

func runScanPostman(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(scanPostmanOpts.apiKey, "POSTMAN_API_KEY")
	if apiKey == "" {
		return errors.New("postman: --api-key is required (or set POSTMAN_API_KEY)")
	}
	cfg := postmanConfig(scanPostmanOpts)
	cfg["api_key"] = apiKey
	return runScanSaaS(cmd, "postman", cfg)
}

func runVerifyPostman(cmd *cobra.Command, _ []string) error {
	apiKey := resolveEnv(verifyPostmanOpts.apiKey, "POSTMAN_API_KEY")
	if apiKey == "" {
		return errors.New("postman: --api-key is required (or set POSTMAN_API_KEY)")
	}
	return runVerifySaaS(cmd, "postman", apiKey, postmanConfig(verifyPostmanOpts))
}
