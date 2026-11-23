package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/custom"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

var detectorsCheckRules string

var detectorsCheckCmd = &cobra.Command{
	Use:   "check --rules FILE",
	Short: "Validate custom rules against their examples and negative_examples",
	Long: "Compile every rule in a custom rules file and run each rule, offline and\n" +
		"through the full scan pipeline (keyword prefilter, checksum, entropy), over\n" +
		"its `examples` (each must yield a finding) and `negative_examples` (none may).\n" +
		"Exits non-zero on any failure, so it can gate rule changes in CI.",
	Args: cobra.NoArgs,
	RunE: runDetectorsCheck,
}

func init() {
	detectorsCheckCmd.Flags().StringVar(&detectorsCheckRules, "rules", "", "path to a custom rules JSON file (required)")
	_ = detectorsCheckCmd.MarkFlagRequired("rules")
	detectorsCmd.AddCommand(detectorsCheckCmd)
}

func runDetectorsCheck(cmd *cobra.Command, _ []string) error {
	dets, err := custom.LoadFile(detectorsCheckRules)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	var failures, checked, untested int
	for _, d := range dets {
		rule := d.Rule()
		if len(rule.Examples) == 0 {
			untested++
			termsafe.Fprintf(out, "WARN  %s: no examples (rule is untested)\n", rule.Name)
		}
		run := func(example string) (int, error) {
			res, err := engine.ScanBytesWithDetectors(cmd.Context(), []detectors.Detector{d}, []byte(example), engine.Options{Concurrency: 1})
			return len(res), err
		}
		for i, ex := range rule.Examples {
			checked++
			n, err := run(ex)
			if err != nil {
				return fmt.Errorf("%s: examples[%d]: %w", rule.Name, i, err)
			}
			if n == 0 {
				failures++
				termsafe.Fprintf(out, "FAIL  %s: examples[%d] produced no finding\n", rule.Name, i)
			}
		}
		for i, ex := range rule.NegativeExamples {
			checked++
			n, err := run(ex)
			if err != nil {
				return fmt.Errorf("%s: negative_examples[%d]: %w", rule.Name, i, err)
			}
			if n > 0 {
				failures++
				termsafe.Fprintf(out, "FAIL  %s: negative_examples[%d] produced %d finding(s)\n", rule.Name, i, n)
			}
		}
	}
	fmt.Fprintf(out, "%d rule(s), %d example(s) checked, %d failure(s), %d rule(s) without examples\n", len(dets), checked, failures, untested)
	if failures > 0 {
		return fmt.Errorf("detectors check: %d example failure(s)", failures)
	}
	return nil
}
