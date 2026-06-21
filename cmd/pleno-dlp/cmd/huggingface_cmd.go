package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// huggingfaceFlags collects the subset of HuggingFace Config that surfaces as
// CLI flags.
type huggingfaceFlags struct {
	org       string
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
	Short: "Scan a HuggingFace organisation or single repo (full commit history)",
	Long: "Scan a HuggingFace organisation or single repo. Reads --token, falling back to the\n" +
		"HF_TOKEN env var. --org and --repo are mutually exclusive; one is required.\n" +
		"Each repo is cloned and every commit is scanned. Use --repo-types to limit to\n" +
		"model, dataset, and/or space repositories (default: all three).",
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
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.org, "org", "", "HuggingFace organisation (author) to scan (mutually exclusive with --repo)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.repo, "repo", "", "single HuggingFace repo in owner/name form (mutually exclusive with --org)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.token, "token", "", "HuggingFace user-access token (falls back to the HF_TOKEN env var)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.apiBase, "api-base", "", "HuggingFace API base URL (default https://huggingface.co)")
	scanHuggingFaceCmd.Flags().StringVar(&scanHuggingFaceOpts.repoTypes, "repo-types", "", "comma-separated repo types to scan: model,dataset,space (default: all)")
	scanCmd.AddCommand(scanHuggingFaceCmd)

	verifyHuggingFaceCmd.Flags().StringVar(&verifyHuggingFaceOpts.token, "token", "", "HuggingFace user-access token (falls back to the HF_TOKEN env var)")
	verifyHuggingFaceCmd.Flags().StringVar(&verifyHuggingFaceOpts.apiBase, "api-base", "", "HuggingFace API base URL (default https://huggingface.co)")
	verifyCmd.AddCommand(verifyHuggingFaceCmd)
}

func runScanHuggingFace(cmd *cobra.Command, _ []string) error {
	if scanHuggingFaceOpts.org == "" && scanHuggingFaceOpts.repo == "" {
		return errors.New("huggingface: one of --org or --repo is required")
	}
	token := resolveHFToken(scanHuggingFaceOpts.token)
	cfg := connectors.Config{
		"org":        scanHuggingFaceOpts.org,
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
