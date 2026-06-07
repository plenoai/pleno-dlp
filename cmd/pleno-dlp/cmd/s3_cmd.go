package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type s3Flags struct {
	bucket       string
	prefix       string
	region       string
	endpoint     string
	include      []string
	exclude      []string
	maxSizeBytes int64
}

var s3Opts s3Flags

var scanS3Cmd = &cobra.Command{
	Use:   "s3 --bucket <name>",
	Short: "Scan objects in an S3 bucket (or S3-compatible store)",
	Args:  cobra.NoArgs,
	RunE:  runScanS3,
}

func init() {
	scanS3Cmd.Flags().StringVar(&s3Opts.bucket, "bucket", "", "S3 bucket name")
	scanS3Cmd.Flags().StringVar(&s3Opts.prefix, "prefix", "", "object key prefix to scope the scan")
	scanS3Cmd.Flags().StringVar(&s3Opts.region, "region", "", "AWS region (default: SDK default credential chain)")
	scanS3Cmd.Flags().StringVar(&s3Opts.endpoint, "endpoint", "", "custom endpoint URL for S3-compatible stores (MinIO, localstack)")
	scanS3Cmd.Flags().StringSliceVar(&s3Opts.include, "include", nil, "glob(s) to include (matched against object keys and basenames)")
	scanS3Cmd.Flags().StringSliceVar(&s3Opts.exclude, "exclude", nil, "glob(s) to exclude")
	scanS3Cmd.Flags().Int64Var(&s3Opts.maxSizeBytes, "max-size", 0, "skip objects larger than this many bytes (0 = default 10 MiB)")
	_ = scanS3Cmd.MarkFlagRequired("bucket")
}

func runScanS3(cmd *cobra.Command, _ []string) error {
	src := sources.New(sources.SourceS3)
	if src == nil {
		return fmt.Errorf("s3 source is not registered (missing pkg/sources/all import?)")
	}
	cfg, err := json.Marshal(map[string]any{
		"bucket":         s3Opts.bucket,
		"prefix":         s3Opts.prefix,
		"region":         s3Opts.region,
		"endpoint":       s3Opts.endpoint,
		"include":        s3Opts.include,
		"exclude":        s3Opts.exclude,
		"max_size_bytes": s3Opts.maxSizeBytes,
	})
	if err != nil {
		return fmt.Errorf("encode source config: %w", err)
	}
	return runScanCommon(cmd, src, cfg, "s3")
}
