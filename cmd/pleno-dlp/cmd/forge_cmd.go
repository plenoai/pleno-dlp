package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type forgeScanFlags struct {
	repo      string
	token     string
	apiBase   string
	account   string
	username  string
	projectID string
}

var forgeScanOpts = map[string]*forgeScanFlags{}

type forgeCommandSpec struct {
	name           string
	env            string
	defaultAPIBase string
}

var forgeCommandSpecs = []forgeCommandSpec{
	{name: "forgejo", env: "FORGEJO_TOKEN"},
	{name: "gitea", env: "GITEA_TOKEN"},
	{name: "gogs", env: "GOGS_TOKEN"},
	{name: "gitbucket", env: "GITBUCKET_TOKEN"},
	{name: "codeberg", env: "CODEBERG_TOKEN", defaultAPIBase: "https://codeberg.org/api/v1"},
	{name: "onedev", env: "ONEDEV_TOKEN"},
	{name: "codebase", env: "CODEBASE_API_KEY", defaultAPIBase: "https://api3.codebasehq.com"},
	{name: "pagure", env: "PAGURE_TOKEN", defaultAPIBase: "https://pagure.io/api/0"},
}

func init() {
	for _, spec := range forgeCommandSpecs {
		spec := spec
		opts := &forgeScanFlags{}
		forgeScanOpts[spec.name] = opts
		cmd := &cobra.Command{
			Use:   spec.name + " --repo <repository>",
			Short: "Scan " + spec.name + " API comments",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runScanForge(cmd, spec.name, spec.env, opts)
			},
		}
		addForgeFlags(cmd, opts, spec)
		scanCmd.AddCommand(cmd)
	}
}

func addForgeFlags(cmd *cobra.Command, opts *forgeScanFlags, spec forgeCommandSpec) {
	cmd.Flags().StringVar(&opts.repo, "repo", "", "repository or project identifier")
	cmd.Flags().StringVar(&opts.token, "token", "", "API token (falls back to "+spec.env+")")
	apiBaseHelp := "API base URL"
	if spec.defaultAPIBase != "" {
		apiBaseHelp += " (default " + spec.defaultAPIBase + ")"
	} else {
		apiBaseHelp += " (required for self-hosted instances)"
	}
	cmd.Flags().StringVar(&opts.apiBase, "api-base", "", apiBaseHelp)
	if spec.name == "codebase" {
		cmd.Flags().StringVar(&opts.account, "account", "", "Codebase account name")
		cmd.Flags().StringVar(&opts.username, "username", "", "Codebase username")
	}
	if spec.name == "onedev" {
		cmd.Flags().StringVar(&opts.projectID, "project-id", "", "OneDev numeric project id; defaults to --repo when numeric")
	}
}

func runScanForge(cmd *cobra.Command, provider, envToken string, opts *forgeScanFlags) error {
	if opts.repo == "" {
		return fmt.Errorf("%s: --repo is required", provider)
	}
	token := opts.token
	if token == "" && envToken != "" {
		token = os.Getenv(envToken)
	}
	cfg := connectors.Config{
		"repo":       opts.repo,
		"token":      token,
		"api_base":   opts.apiBase,
		"account":    opts.account,
		"username":   opts.username,
		"project_id": opts.projectID,
	}
	return runScanSaaS(cmd, provider, cfg)
}
