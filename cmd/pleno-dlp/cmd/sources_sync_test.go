// Sync test: rejects drift between catalog.All() (the runtime source/
// connector registry union) and scanCmd's actual subcommand tree. Mirrors
// pkg/detectors/verifycoverage_test.go's doc/code drift guard, but here
// both sides are code — there is no third hand-maintained doc to parse.
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"

	"github.com/plenoai/pleno-dlp/pkg/sources/catalog"
)

// plannedSources are connectors registered in pkg/connectors with
// deliberately no `scan <name>` subcommand yet (docs/counts.md tracks the
// published wired-source count; the issues remain the planning reference).
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

// TestImplementedSourceCount checks the published count against the runtime registry.
func TestImplementedSourceCount(t *testing.T) {
	entries := catalog.All()
	implemented := 0
	for _, e := range entries {
		if !plannedSources[e.Name] {
			implemented++
		}
	}
	want := docScanSourceCount(t)
	if implemented != want {
		t.Errorf("CLI-wired source count = %d, but docs/counts.md prints %d "+
			"— update the doc's `Current value` line or the registry so they agree", implemented, want)
	}
	if len(plannedSources) != 3 {
		t.Errorf("plannedSources has %d entries, want 3 (update this planning list if this changed intentionally)", len(plannedSources))
	}
}

// docScanSourceCount returns the pleno-dlp wired-source count printed in
// docs/counts.md's `Current value` line. Parsing it makes the public
// definition page a real input to the drift gate rather than a hand-synced
// number the test never inspects.
func docScanSourceCount(t *testing.T) int {
	t.Helper()
	// test cwd is the package dir (cmd/pleno-dlp/cmd); the doc lives at repo root.
	path := filepath.Join("..", "..", "..", "docs", "counts.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?m)^\*\*Current value:\*\*\s*(\d+) wired sources\.`)
	m := re.FindSubmatch(b)
	if m == nil {
		t.Fatalf("no `**Current value:** N wired sources.` line found in %s — the drift gate cannot read the doc's count", path)
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse Scan sources count %q: %v", m[1], err)
	}
	return n
}
