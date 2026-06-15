package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type gcsFlags struct {
	bucket             string
	prefix             string
	serviceAccountJSON string
	include            []string
	exclude            []string
	maxSizeBytes       int64
}

var gcsOpts gcsFlags

var scanGCSCmd = &cobra.Command{
	Use:   "gcs --bucket <name>",
	Short: "Scan objects in a Google Cloud Storage bucket",
	Args:  cobra.NoArgs,
	RunE:  runScanGCS,
}

func init() {
	scanGCSCmd.Flags().StringVar(&gcsOpts.bucket, "bucket", "", "GCS bucket name")
	scanGCSCmd.Flags().StringVar(&gcsOpts.prefix, "prefix", "", "object name prefix to scope the scan")
	scanGCSCmd.Flags().StringVar(&gcsOpts.serviceAccountJSON, "service-account-json", "", "path to a service account JSON key file (default: Application Default Credentials)")
	scanGCSCmd.Flags().StringSliceVar(&gcsOpts.include, "include", nil, "glob(s) to include (matched against object names and basenames)")
	scanGCSCmd.Flags().StringSliceVar(&gcsOpts.exclude, "exclude", nil, "glob(s) to exclude")
	scanGCSCmd.Flags().Int64Var(&gcsOpts.maxSizeBytes, "max-size", 0, "skip objects larger than this many bytes (0 = default 10 MiB)")
	_ = scanGCSCmd.MarkFlagRequired("bucket")
}

func runScanGCS(cmd *cobra.Command, _ []string) error {
	src := sources.New(sources.SourceGCS)
	if src == nil {
		return fmt.Errorf("gcs source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"bucket":               gcsOpts.bucket,
		"prefix":               gcsOpts.prefix,
		"service_account_json": gcsOpts.serviceAccountJSON,
		"include":              gcsOpts.include,
		"exclude":              gcsOpts.exclude,
		"max_size_bytes":       gcsOpts.maxSizeBytes,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "gcs")
}
