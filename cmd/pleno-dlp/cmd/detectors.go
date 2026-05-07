// Operator-facing introspection over the registered detector set. Lives
// alongside scan.go so both commands share Root and the blank-imports
// that populate the detector registry — the list output stays in sync
// with whatever the scanner actually runs without a hand-maintained map.
package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// detectorsCmd is the parent for all introspection subcommands. Today
// only `list` exists; future siblings (`describe <type>`, `keywords
// <type>`) attach here without crowding the top-level help.
var detectorsCmd = &cobra.Command{
	Use:   "detectors",
	Short: "Introspect the registered detector set",
}

// listFormat captures the --format choice. Stays in this file rather
// than alongside scanFlags because scan and detectors output are
// independent — the flag parser shouldn't suggest cross-talk between
// them.
type detectorsListFlags struct {
	format string
}

var detectorsListOpts detectorsListFlags

var detectorsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every registered detector",
	Long: "List every registered detector — useful for confirming what " +
		"a given pleno-dlp build actually scans for. The same registry " +
		"powers `scan`, so list output and scan coverage cannot drift.",
	Args: cobra.NoArgs,
	RunE: runDetectorsList,
}

func init() {
	detectorsListCmd.Flags().StringVar(&detectorsListOpts.format, "format", "table", "output format: table, json, names")

	detectorsCmd.AddCommand(detectorsListCmd)
	Root.AddCommand(detectorsCmd)
}

// detectorRecord is the JSON shape one row maps to. Stable wire format
// — additions go at the end, never reorder, so downstream tooling
// (audit dashboards, CI matrices) can pin to fields they care about.
type detectorRecord struct {
	Type     string   `json:"type"`
	Keywords []string `json:"keywords"`
	Verifies bool     `json:"verifies"`
}

func runDetectorsList(cmd *cobra.Command, _ []string) error {
	rows := buildDetectorRecords()

	switch strings.ToLower(strings.TrimSpace(detectorsListOpts.format)) {
	case "", "table":
		return writeDetectorTable(cmd.OutOrStdout(), rows)
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "names":
		// One detector type per line — what `--list-detectors | grep`
		// or `xargs` users want. Sorted alphabetically so consecutive
		// runs are byte-identical (assertable in CI).
		for _, r := range rows {
			fmt.Fprintln(cmd.OutOrStdout(), r.Type)
		}
		return nil
	default:
		return fmt.Errorf("--format: unknown value %q (valid: table, json, names)", detectorsListOpts.format)
	}
}

// buildDetectorRecords snapshots the registry into a stable-ordered
// slice. The source of truth is detectors.All(); we sort by type name
// so output is deterministic across runs (Go map iteration order isn't).
func buildDetectorRecords() []detectorRecord {
	all := detectors.All()
	out := make([]detectorRecord, 0, len(all))
	for _, d := range all {
		_, hasVerify := d.(detectors.Verifier)
		out = append(out, detectorRecord{
			Type:     d.Type().String(),
			Keywords: d.Keywords(),
			Verifies: hasVerify,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func writeDetectorTable(w cobraWriter, rows []detectorRecord) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DETECTOR\tVERIFIES\tKEYWORDS")
	for _, r := range rows {
		// Cap keyword list at 3 entries per row — the full set is
		// available via --format=json. Keeps the table narrow enough
		// for an 80-column terminal.
		kw := r.Keywords
		more := ""
		if len(kw) > 3 {
			kw = kw[:3]
			more = fmt.Sprintf(" +%d more", len(r.Keywords)-3)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s%s\n", r.Type, verifyMark(r.Verifies), strings.Join(kw, ", "), more)
	}
	fmt.Fprintf(tw, "\n%d detector(s) registered\n", len(rows))
	return tw.Flush()
}

// verifyMark renders a stable checkmark for the table. Unicode glyphs
// chosen to match the scan output's tablesink so the two look the
// same at a glance.
func verifyMark(b bool) string {
	if b {
		return "✓"
	}
	return "—"
}

// cobraWriter narrows io.Writer to the surface tabwriter needs. Only
// declared so the function signature reads as "writes structured table
// output" rather than "takes any byte sink".
type cobraWriter = interface {
	Write(p []byte) (int, error)
}
