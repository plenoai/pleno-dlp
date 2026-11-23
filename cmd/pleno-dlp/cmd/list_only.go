package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

// runListOnly prints the repositories connector name would scan for cfg and
// returns without scanning (--list-only). --format json/jsonl emit
// machine-readable entries; every other format prints one clone URL per
// line.
func runListOnly(cmd *cobra.Command, name string, cfg connectors.Config) error {
	repos, err := connectors.ListRepositories(cmd.Context(), name, cfg)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	switch scanOpts.format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if repos == nil {
			repos = []connectors.Repository{}
		}
		return enc.Encode(repos)
	case "jsonl":
		enc := json.NewEncoder(out)
		for _, r := range repos {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	for _, r := range repos {
		termsafe.Fprintf(out, "%s\n", r.URL)
	}
	if !scanOpts.quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s: %d repositor(ies) listed; nothing scanned (--list-only)\n", name, len(repos))
	}
	return nil
}
