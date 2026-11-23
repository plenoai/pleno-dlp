// Command kingfisher-checks prints, as JSON, how pkg/detectors/catalog
// verifies each kingfisher rule it carries a check for ({"rule": kind}).
// scripts/kingfisher-parity.py reads it to fill the parity doc's
// verified column (issue #934).
package main

import (
	"encoding/json"
	"os"

	"github.com/plenoai/pleno-dlp/pkg/detectors/catalog"
)

func main() {
	out := map[string]string{}
	for _, id := range catalog.VerifiedRules() {
		out[id] = catalog.CheckKind(id)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		os.Exit(1)
	}
}
