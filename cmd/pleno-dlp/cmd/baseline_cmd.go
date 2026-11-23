package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

const defaultBaselinePath = ".pleno-baseline.json"

var baselineOpts struct {
	input   string
	output  string
	force   bool
	noPrune bool
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Create or update a baseline of accepted findings",
	Long: "Record the current findings as accepted so later scans with --baseline report only new ones.\n\n" +
		"The input is a JSON report from 'pleno-dlp scan ... --format json' (stdin by default). Baselines\n" +
		"store only the stable fingerprint, detector, path, and redacted display — never raw secrets.\n\n" +
		"  pleno-dlp scan filesystem . --format json --fail-on any | pleno-dlp baseline create\n" +
		"  pleno-dlp scan filesystem . --baseline .pleno-baseline.json   # only new findings\n" +
		"  pleno-dlp scan filesystem . --format json | pleno-dlp baseline update\n\n" +
		"See docs/baseline.md.",
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Write a new baseline from a JSON scan report",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if !baselineOpts.force {
			if _, err := os.Stat(baselineOpts.output); err == nil {
				return fmt.Errorf("baseline create: %s exists; use 'baseline update' or --force", baselineOpts.output)
			}
		}
		entries, err := readBaselineReport(cmd)
		if err != nil {
			return err
		}
		b, added, _ := (*engine.Baseline)(nil).Merge(entries, true)
		if err := engine.WriteBaselineFile(baselineOpts.output, b); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "baseline: wrote %s (%d finding(s))\n", baselineOpts.output, added)
		return nil
	},
}

var baselineUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Merge a JSON scan report into an existing baseline",
	Long: "Add new findings from the report and, unless --no-prune is given, drop entries whose findings\n" +
		"no longer appear (fixed or removed secrets). Generate the report without --baseline, or with\n" +
		"--baseline --show-suppressed, so already-accepted findings are still present in it.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		old, err := engine.LoadBaselineFile(baselineOpts.output)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			old = nil
		}
		entries, err := readBaselineReport(cmd)
		if err != nil {
			return err
		}
		b, added, removed := old.Merge(entries, !baselineOpts.noPrune)
		if err := engine.WriteBaselineFile(baselineOpts.output, b); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "baseline: updated %s (+%d, -%d, %d total)\n", baselineOpts.output, added, removed, len(b.Findings))
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{baselineCreateCmd, baselineUpdateCmd} {
		c.Flags().StringVarP(&baselineOpts.input, "input", "i", "-", "JSON scan report to read ('-' for stdin)")
		c.Flags().StringVarP(&baselineOpts.output, "output", "o", defaultBaselinePath, "baseline file to write")
		baselineCmd.AddCommand(c)
	}
	baselineCreateCmd.Flags().BoolVar(&baselineOpts.force, "force", false, "overwrite an existing baseline file")
	baselineUpdateCmd.Flags().BoolVar(&baselineOpts.noPrune, "no-prune", false, "keep entries whose findings are absent from the report")
	Root.AddCommand(baselineCmd)
}

// baselineReportRecord is the subset of the JSON output schema a baseline
// needs.
type baselineReportRecord struct {
	Fingerprint  string `json:"fingerprint"`
	Detector     string `json:"detector"`
	Path         string `json:"path"`
	Redacted     string `json:"redacted"`
	SuppressedBy string `json:"suppressed_by"`
}

func readBaselineReport(cmd *cobra.Command) ([]engine.BaselineEntry, error) {
	var r io.Reader = cmd.InOrStdin()
	if baselineOpts.input != "-" {
		f, err := os.Open(baselineOpts.input)
		if err != nil {
			return nil, fmt.Errorf("baseline: open report: %w", err)
		}
		defer f.Close()
		r = f
	}
	var recs []baselineReportRecord
	if err := json.NewDecoder(r).Decode(&recs); err != nil {
		return nil, fmt.Errorf("baseline: report must be the JSON array from --format json: %w", err)
	}
	out := make([]engine.BaselineEntry, 0, len(recs))
	for i, rec := range recs {
		// Audit records from --show-suppressed: keep only those the
		// baseline itself suppressed, so update does not prune them.
		// Findings muted by placeholders, inline pragmas, or the
		// allowlist are already handled by those mechanisms.
		if rec.SuppressedBy != "" && rec.SuppressedBy != engine.SuppressedByBaseline {
			continue
		}
		if rec.Fingerprint == "" {
			return nil, fmt.Errorf("baseline: report record %d has no fingerprint (produced by an older pleno-dlp?)", i)
		}
		out = append(out, engine.BaselineEntry{
			Fingerprint: rec.Fingerprint,
			Detector:    rec.Detector,
			Path:        rec.Path,
			Redacted:    rec.Redacted,
		})
	}
	return out, nil
}
