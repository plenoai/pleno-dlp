package cmd

import (
	"errors"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// huggingfaceFlags collects the subset of HuggingFace Config that surfaces as
// CLI flags.
type huggingfaceFlags struct {
	org       []string
	user      []string
	bucket    []string
	repo      string
	token     string
	apiBase   string
	repoTypes string
}

var (
	scanHuggingFaceOpts   huggingfaceFlags
	verifyHuggingFaceOpts huggingfaceFlags
)

var scanHuggingFaceCmd = &cobra.Command{
	Use:   "huggingface",
	Short: "Scan HuggingFace users, organisations, repos, and storage buckets",
	Long: "Scan HuggingFace users, organisations, a single repo, and storage buckets. Reads\n" +
		"--token, falling back to the HF_TOKEN env var. --org/--user and --repo are mutually\n" +
		"exclusive. Each model/dataset/space repo is cloned and every commit is scanned;\n" +
		"bucket objects are listed and downloaded. Use --repo-types to limit owner\n" +
		"enumeration to model, dataset, space, and/or bucket (default: all four).",
	Args: cobra.NoArgs,
	RunE: runScanHuggingFace,
}

var verifyHuggingFaceCmd = &cobra.Command{
	Use:   "huggingface",
	Short: "Verify a HuggingFace user-access token (calls GET /api/whoami-v2)",
	Args:  cobra.NoArgs,
	RunE:  runVerifyHuggingFace,
}

func init() {
	scanHuggingFaceCmd.Flags().StringSliceVar(&scanHuggingFaceOpts.org, "org", nil, "HuggingFace organisation(s) to scan; repeatable or comma-separated (mutually exclusive with --repo)")
	scanHuggingFaceCmd.Flags().StringSliceVar(&scanHuggingFaceOpts.user, "user", nil, "HuggingFace user(s) to scan; repeatable or comma-separated (mutually exclusive with --repo)")
	scanHuggingFaceCmd.Flags().StringSliceVar(&scanHuggingFaceOpts.bucket, "bucket", nil, "HuggingFace storage bucket(s): owner/name[/prefix], hf://buckets/..., or bucket URL; repeatable")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.repo, "repo", "", "single HuggingFace repo in owner/name form (mutually exclusive with --org)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.token, "token", "", "HuggingFace user-access token (falls back to the HF_TOKEN env var)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.apiBase, "api-base", "", "HuggingFace API base URL (default https://huggingface.co)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.repoTypes, "repo-types", "", "comma-separated types to enumerate for --org/--user: model,dataset,space,bucket (default: all)")
	scanCmd.AddCommand(scanHuggingFaceCmd)

	verifyHuggingFaceCmd.Flags().StringVar(&verifyHuggingFaceOpts.token, "token", "", "HuggingFace user-access token (falls back to the HF_TOKEN env var)")
	verifyHuggingFaceCmd.Flags().StringVar(&verifyHuggingFaceOpts.apiBase, "api-base", "", "HuggingFace API base URL (default https://huggingface.co)")
	verifyCmd.AddCommand(verifyHuggingFaceCmd)
}

func runScanHuggingFace(cmd *cobra.Command, _ []string) error {
	o := scanHuggingFaceOpts
	if len(o.org) == 0 && len(o.user) == 0 && o.repo == "" && len(o.bucket) == 0 {
		return errors.New("huggingface: one of --org, --user, --repo, or --bucket is required")
	}
	token := resolveHFToken(scanHuggingFaceOpts.token)
	cfg := connectors.Config{
		"org":        strings.Join(o.org, ","),
		"user":       strings.Join(o.user, ","),
		"bucket":     strings.Join(o.bucket, ","),
		"repo":       scanHuggingFaceOpts.repo,
		"api_base":   scanHuggingFaceOpts.apiBase,
		"repo_types": scanHuggingFaceOpts.repoTypes,
	}
	if token != "" {
		cfg["token"] = token
	}
	return runScanSaaS(cmd, "huggingface", cfg)
}

func runVerifyHuggingFace(cmd *cobra.Command, _ []string) error {
	token := resolveHFToken(verifyHuggingFaceOpts.token)
	if token == "" {
		return errors.New("huggingface: --token is required (or set the HF_TOKEN env var)")
	}
	return runVerifySaaS(cmd, "huggingface", token, connectors.Config{
		"api_base": verifyHuggingFaceOpts.apiBase,
	})
}

func resolveHFToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("HF_TOKEN"); v != "" {
		return v
	}
	return os.Getenv("HUGGING_FACE_HUB_TOKEN")
}
