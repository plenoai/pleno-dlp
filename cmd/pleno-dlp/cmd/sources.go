// Operator-facing introspection over the registered source/connector set.
// Symmetric with detectors.go: same registry-backed guarantee that list
// output cannot drift from what `scan` actually runs, plus CLI-WIRED to
// surface connectors registered in pkg/connectors that have no `scan`
// subcommand yet.
package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/sources/catalog"
)

var sourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "Introspect the registered source and connector set",
}

type sourcesListFlags struct {
	format string
}

var sourcesListOpts sourcesListFlags

var sourcesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every registered core source and SaaS connector",
	Long: "List every registered core source and SaaS connector. CLI-WIRED " +
		"marks whether a `pleno-dlp scan <name>` subcommand exists; entries " +
		"without one are registered in pkg/connectors but not yet reachable " +
		"from the CLI (tracked as planned in docs/comparison.md).",
	Args: cobra.NoArgs,
	RunE: runSourcesList,
}

func init() {
	sourcesListCmd.Flags().StringVar(&sourcesListOpts.format, "format", "table", "output format: table, json, names")
	sourcesCmd.AddCommand(sourcesListCmd)
	Root.AddCommand(sourcesCmd)
}

// sourceRecord is the JSON shape for one row.
type sourceRecord struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	CLIWired bool   `json:"cli_wired"`
}

func runSourcesList(cmd *cobra.Command, _ []string) error {
	rows := buildSourceRecords()

	switch strings.ToLower(strings.TrimSpace(sourcesListOpts.format)) {
	case "", "table":
		return writeSourceTable(cmd.OutOrStdout(), rows)
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "names":
		for _, r := range rows {
			fmt.Fprintln(cmd.OutOrStdout(), r.Name)
		}
		return nil
	default:
		return fmt.Errorf("--format: unknown value %q (valid: table, json, names)", sourcesListOpts.format)
	}
}

// buildSourceRecords snapshots the catalog into a stable-ordered slice,
// annotated with the live scanCmd subcommand tree.
func buildSourceRecords() []sourceRecord {
	wired := cliWiredSourceNames()
	entries := catalog.All()
	out := make([]sourceRecord, 0, len(entries))
	for _, e := range entries {
		out = append(out, sourceRecord{
			Name:     e.Name,
			Category: string(e.Category),
			CLIWired: wired[e.Name],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// cliWiredSourceNames returns the set of `scan <name>` subcommand names
// actually registered under scanCmd — the CLI-facing ground truth that
// sources_sync_test.go cross-checks against catalog.All() so the two
// cannot drift.
func cliWiredSourceNames() map[string]bool {
	cmds := scanCmd.Commands()
	wired := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		wired[c.Name()] = true
	}
	return wired
}

func writeSourceTable(w cobraWriter, rows []sourceRecord) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tCATEGORY\tCLI-WIRED")

	wiredCount := 0
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join([]string{r.Name, r.Category, verifyMark(r.CLIWired)}, "\t"))
		if r.CLIWired {
			wiredCount++
		}
	}
	fmt.Fprintf(tw, "\n%d source(s) registered, %d wired to a scan subcommand\n", len(rows), wiredCount)
	return tw.Flush()
}
