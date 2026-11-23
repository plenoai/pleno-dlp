package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type azureDevOpsFlags struct {
	token   string
	org     string
	project string
	baseURL string
}

var (
	scanAzureDevOpsOpts   azureDevOpsFlags
	verifyAzureDevOpsOpts azureDevOpsFlags
)

var scanAzureDevOpsCmd = &cobra.Command{
	Use:   "azure-devops --org <org>",
	Short: "Scan the full Git history of Azure DevOps repositories",
	Long: "Clone every Git repository in an Azure DevOps organization (or one --project)\n" +
		"and scan all branches and tags. Reads --token, falling back to AZURE_DEVOPS_PAT\n" +
		"(a PAT with Code: Read). With --incremental, only commits added since the\n" +
		"previous run are walked.",
	Args: cobra.NoArgs,
	RunE: runScanAzureDevOps,
}

var verifyAzureDevOpsCmd = &cobra.Command{
	Use:   "azure-devops --org <org>",
	Short: "Verify an Azure DevOps personal access token",
	Args:  cobra.NoArgs,
	RunE:  runVerifyAzureDevOps,
}

func init() {
	for _, c := range []struct {
		cmd  *cobra.Command
		opts *azureDevOpsFlags
	}{{scanAzureDevOpsCmd, &scanAzureDevOpsOpts}, {verifyAzureDevOpsCmd, &verifyAzureDevOpsOpts}} {
		c.cmd.Flags().StringVar(&c.opts.token, "token", "", "Azure DevOps personal access token (falls back to AZURE_DEVOPS_PAT)")
		c.cmd.Flags().StringVar(&c.opts.org, "org", "", "Azure DevOps organization name")
		c.cmd.Flags().StringVar(&c.opts.baseURL, "base-url", "", "service URL (default https://dev.azure.com; Azure DevOps Server: https://<host>/tfs)")
		_ = c.cmd.MarkFlagRequired("org")
	}
	scanAzureDevOpsCmd.Flags().StringVar(&scanAzureDevOpsOpts.project, "project", "", "only scan repositories in this project")
	scanCmd.AddCommand(scanAzureDevOpsCmd)
	verifyCmd.AddCommand(verifyAzureDevOpsCmd)
}

func runScanAzureDevOps(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(scanAzureDevOpsOpts.token, "AZURE_DEVOPS_PAT")
	if token == "" {
		return errors.New("azure-devops: --token is required (or set AZURE_DEVOPS_PAT)")
	}
	return runScanSaaS(cmd, "azure-devops", connectors.Config{
		"token":    token,
		"org":      scanAzureDevOpsOpts.org,
		"project":  scanAzureDevOpsOpts.project,
		"base_url": scanAzureDevOpsOpts.baseURL,
	})
}

func runVerifyAzureDevOps(cmd *cobra.Command, _ []string) error {
	token := resolveEnv(verifyAzureDevOpsOpts.token, "AZURE_DEVOPS_PAT")
	if token == "" {
		return errors.New("azure-devops: --token is required (or set AZURE_DEVOPS_PAT)")
	}
	return runVerifySaaS(cmd, "azure-devops", token, connectors.Config{
		"org":      verifyAzureDevOpsOpts.org,
		"base_url": verifyAzureDevOpsOpts.baseURL,
	})
}
