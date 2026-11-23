package cmd

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

type azureBlobFlags struct {
	containerURL string
	sasToken     string
	prefix       string
	maxSizeBytes int64
}

var azureBlobOpts azureBlobFlags

var scanAzureBlobCmd = &cobra.Command{
	Use:   "azure-blob --container-url <url>",
	Short: "Scan blobs in an Azure Blob Storage container (SAS auth)",
	Long: "Scan every blob in one Azure Blob Storage container.\n" +
		"--container-url is https://<account>.blob.core.windows.net/<container>.\n" +
		"The SAS comes from --sas-token, AZURE_STORAGE_SAS_TOKEN, or a query string on\n" +
		"--container-url; it needs list (l) and read (r) permissions. The SAS is never\n" +
		"written to findings, errors, or logs. With --incremental, blobs whose ETag is\n" +
		"unchanged since the previous run are skipped.",
	Args: cobra.NoArgs,
	RunE: runScanAzureBlob,
}

func init() {
	scanAzureBlobCmd.Flags().StringVar(&azureBlobOpts.containerURL, "container-url", "", "container URL, https://<account>.blob.core.windows.net/<container>")
	scanAzureBlobCmd.Flags().StringVar(&azureBlobOpts.sasToken, "sas-token", "", "SAS query string (falls back to AZURE_STORAGE_SAS_TOKEN)")
	scanAzureBlobCmd.Flags().StringVar(&azureBlobOpts.prefix, "prefix", "", "only scan blobs whose name starts with this prefix")
	scanAzureBlobCmd.Flags().Int64Var(&azureBlobOpts.maxSizeBytes, "max-size", 0, "skip blobs larger than this many bytes (0 = default 10 MiB)")
	_ = scanAzureBlobCmd.MarkFlagRequired("container-url")
	scanCmd.AddCommand(scanAzureBlobCmd)
}

func runScanAzureBlob(cmd *cobra.Command, _ []string) error {
	cfg := connectors.Config{
		"container_url": azureBlobOpts.containerURL,
		"sas_token":     resolveEnv(azureBlobOpts.sasToken, "AZURE_STORAGE_SAS_TOKEN"),
		"prefix":        azureBlobOpts.prefix,
	}
	if azureBlobOpts.maxSizeBytes > 0 {
		cfg["max_size_bytes"] = strconv.FormatInt(azureBlobOpts.maxSizeBytes, 10)
	}
	return runScanSaaS(cmd, "azure-blob", cfg)
}
