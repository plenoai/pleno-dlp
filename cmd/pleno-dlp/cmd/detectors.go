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
	"github.com/plenoai/pleno-dlp/pkg/detectors/verifycoverage"
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

// detectorRecord is the JSON shape one row maps to. Stable wire format
// — additions go at the end, never reorder, so downstream tooling
// (audit dashboards, CI matrices) can pin to fields they care about.
type detectorRecord struct {
	Type     string   `json:"type"`
	Keywords []string `json:"keywords"`
	Verifies bool     `json:"verifies"`
	// VerifyStatus is "verified" | "unverified-by-design" | "verify-gap".
	// Empty when --verify-status is not requested so the JSON shape
	// stays minimal for callers that do not care about the audit class.
	VerifyStatus string `json:"verify_status,omitempty"`
	// Revokes reports whether the detector implements detectors.Revoker.
	// `false` does not always mean "not implementable" — for many
	// providers there is simply no public revocation API. See
	// RevokeStatus for the human-readable classification.
	Revokes bool `json:"revokes,omitempty"`
	// RevokeStatus is "supported" | "context-required" | "unsupported".
	// Empty when --revoke-support is not requested so the JSON shape
	// stays minimal for callers that do not care about revoke routing.
	RevokeStatus string `json:"revoke_status,omitempty"`
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

// revokeContextRequired enumerates detectors whose Revoker
// implementation is wired but cannot run without operator-supplied
// principal context (e.g. AWS needs admin IAM creds + the target IAM
// user name; the access-key id alone is insufficient). These render
// as "context-required" rather than plain "supported" so audit
// readers can see they need extra setup before scan
// --revoke-on-verified will revoke them.
//
// Pinned to DetectorType identifiers (not name strings) so renames in
// the wire-stable enum cannot silently flip a row's classification.
var revokeContextRequired = map[detectors.DetectorType]struct{}{
	detectors.AWS: {},
}

// annotateRevokeSupport fills RevokeStatus on each row using the
// implementation surface plus the context-required allowlist:
//
//   - implements Revoker AND in revokeContextRequired → "context-required"
//   - implements Revoker → "supported"
//   - does not implement Revoker → "unsupported"
//
// We deliberately do not distinguish "no public API" from "not yet
// implemented" here — that is a docs/revoke-support.md concern. The
// CLI flag's job is to answer "would scan --revoke-on-verified do
// anything for this detector?", and that question is binary at the
// implementation layer.
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
		// Cap keyword list at 3 entries per row — the full set is
		// available via --format=json. Keeps the table narrow enough
		// for an 80-column terminal.
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
