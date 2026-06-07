// Operator-facing introspection over the registered detector set.
package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/verifycoverage"
)

var detectorsCmd = &cobra.Command{
	Use:   "detectors",
	Short: "Introspect the registered detector set",
}

type detectorsListFlags struct {
	format        string
	verifyStatus  bool
	revokeSupport bool
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
	detectorsListCmd.Flags().BoolVar(&detectorsListOpts.verifyStatus, "verify-status", false,
		"include verify-coverage class per detector "+
			"(verified, unverified-by-design, verify-gap) — "+
			"sourced from docs/verify-coverage.md")
	detectorsListCmd.Flags().BoolVar(&detectorsListOpts.revokeSupport, "revoke-support", false,
		"include revoke-support class per detector "+
			"(supported, context-required, unsupported) — "+
			"see docs/revoke-support.md for the full provider matrix")

	detectorsCmd.AddCommand(detectorsListCmd)
	Root.AddCommand(detectorsCmd)
}

// detectorRecord is the JSON shape for one row.
type detectorRecord struct {
	Type         string   `json:"type"`
	Keywords     []string `json:"keywords"`
	Verifies     bool     `json:"verifies"`
	VerifyStatus string   `json:"verify_status,omitempty"`
	Revokes      bool     `json:"revokes,omitempty"`
	RevokeStatus string   `json:"revoke_status,omitempty"`
}

func runDetectorsList(cmd *cobra.Command, _ []string) error {
	rows := buildDetectorRecords()
	if detectorsListOpts.verifyStatus {
		annotateVerifyStatus(rows)
	}
	if detectorsListOpts.revokeSupport {
		annotateRevokeSupport(rows)
	}

	switch strings.ToLower(strings.TrimSpace(detectorsListOpts.format)) {
	case "", "table":
		return writeDetectorTable(cmd.OutOrStdout(), rows)
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "names":
		for _, r := range rows {
			fmt.Fprintln(cmd.OutOrStdout(), r.Type)
		}
		return nil
	default:
		return fmt.Errorf("--format: unknown value %q (valid: table, json, names)", detectorsListOpts.format)
	}
}

// buildDetectorRecords snapshots the registry into a stable-ordered slice.
func buildDetectorRecords() []detectorRecord {
	all := detectors.All()
	out := make([]detectorRecord, 0, len(all))
	for _, d := range all {
		_, hasVerify := d.(detectors.Verifier)
		_, hasRevoke := d.(detectors.Revoker)
		out = append(out, detectorRecord{
			Type:     d.Type().String(),
			Keywords: d.Keywords(),
			Verifies: hasVerify,
			Revokes:  hasRevoke,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// revokeContextRequired enumerates detectors that need extra operator context.
var revokeContextRequired = map[detectors.DetectorType]struct{}{
	detectors.AWS: {},
}

// annotateRevokeSupport fills RevokeStatus from implementation plus allowlist.
func annotateRevokeSupport(rows []detectorRecord) {
	all := detectors.All()
	byName := make(map[string]detectors.DetectorType, len(all))
	for _, d := range all {
		byName[d.Type().String()] = d.Type()
	}
	for i := range rows {
		t, ok := byName[rows[i].Type]
		switch {
		case !rows[i].Revokes:
			rows[i].RevokeStatus = "unsupported"
		case ok && contextRequired(t):
			rows[i].RevokeStatus = "context-required"
		default:
			rows[i].RevokeStatus = "supported"
		}
		_ = ok
	}
}

func contextRequired(t detectors.DetectorType) bool {
	_, ok := revokeContextRequired[t]
	return ok
}

func writeDetectorTable(w cobraWriter, rows []detectorRecord) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	withVerify := detectorsListOpts.verifyStatus
	withRevoke := detectorsListOpts.revokeSupport

	header := []string{"DETECTOR", "VERIFIES"}
	if withVerify {
		header = append(header, "VERIFY-STATUS")
	}
	if withRevoke {
		header = append(header, "REVOKES", "REVOKE-STATUS")
	}
	header = append(header, "KEYWORDS")
	fmt.Fprintln(tw, strings.Join(header, "\t"))

	for _, r := range rows {
		kw := r.Keywords
		more := ""
		if len(kw) > 3 {
			kw = kw[:3]
			more = fmt.Sprintf(" +%d more", len(r.Keywords)-3)
		}
		row := []string{r.Type, verifyMark(r.Verifies)}
		if withVerify {
			row = append(row, r.VerifyStatus)
		}
		if withRevoke {
			row = append(row, verifyMark(r.Revokes), r.RevokeStatus)
		}
		row = append(row, strings.Join(kw, ", ")+more)
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	fmt.Fprintf(tw, "\n%d detector(s) registered\n", len(rows))
	return tw.Flush()
}

// annotateVerifyStatus fills VerifyStatus on each row using the doc's
// classification. The rule mirrors verify-coverage.md:
//
//   - hasVerify  → "verified" (class a, the open-set complement; the
//     doc never lists class=a entries)
//   - !hasVerify → look up Classes for "unverified-by-design" / "verify-gap"
//   - !hasVerify and not in Classes → "unknown" (a doc bug; CI test
//     would fail before such a binary ships, but render it so the
//     operator can spot it)
func annotateVerifyStatus(rows []detectorRecord) {
	for i := range rows {
		if rows[i].Verifies {
			rows[i].VerifyStatus = verifycoverage.ClassVerified.Label()
			continue
		}
		if c, ok := verifycoverage.Lookup(rows[i].Type); ok {
			rows[i].VerifyStatus = c.Label()
		} else {
			rows[i].VerifyStatus = "unknown"
		}
	}
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
