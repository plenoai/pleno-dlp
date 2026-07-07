// Sync test: rejects drift between catalog.All() (the runtime source/
// connector registry union) and scanCmd's actual subcommand tree. Mirrors
// pkg/detectors/verifycoverage_test.go's doc/code drift guard, but here
// both sides are code — there is no third hand-maintained doc to parse.
package cmd

import (
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"

	"github.com/plenoai/pleno-dlp/pkg/sources/catalog"
)

// plannedSources are connectors registered in pkg/connectors with
// deliberately no `scan <name>` subcommand yet (docs/comparison.md §9
// tracks them as planned: elasticsearch #217, jenkins #218, postman #219).
// When a subcommand ships, delete the entry here — the test below then
// forces it, since a wired planned entry fails as loudly as an unwired
// implemented one.
var plannedSources = map[string]bool{
	"elasticsearch": true,
	"jenkins":       true,
	"postman":       true,
}

func TestSourceCatalogMatchesCLIWiring(t *testing.T) {
	wired := cliWiredSourceNames()
	entries := catalog.All()
	if len(entries) == 0 {
		t.Fatal("catalog.All() returned no entries; is pkg/sources/all blank-imported by this test binary?")
	}

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		seen[e.Name] = true
		switch {
		case plannedSources[e.Name] && wired[e.Name]:
			t.Errorf("%s: listed in plannedSources but has a scan subcommand now — remove it from plannedSources", e.Name)
		case !plannedSources[e.Name] && !wired[e.Name]:
			t.Errorf("%s: registered in catalog.All() but no `scan %s` subcommand exists — wire it, or mark it planned in plannedSources", e.Name, e.Name)
		}
	}
	for name := range wired {
		if !seen[name] {
			t.Errorf("scan subcommand %q has no catalog.All() entry — register it via sources.Register or connectors.Register", name)
		}
	}
}

// TestImplementedSourceCount pins the count docs/comparison.md §1 and §9
// state in prose, so adding/removing a source or a plannedSources entry
// without updating that prose fails CI instead of drifting silently.
func TestImplementedSourceCount(t *testing.T) {
	entries := catalog.All()
	implemented := 0
	for _, e := range entries {
		if !plannedSources[e.Name] {
			implemented++
		}
	}
	const want = 28
	if implemented != want {
		t.Errorf("CLI-wired source count = %d, want %d (update docs/comparison.md §1/§9 if this changed intentionally)", implemented, want)
	}
	if len(plannedSources) != 3 {
		t.Errorf("plannedSources has %d entries, want 3 (update docs/comparison.md §9 if this changed intentionally)", len(plannedSources))
	}
}
