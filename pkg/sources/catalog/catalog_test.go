package catalog_test

import (
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"

	"github.com/plenoai/pleno-dlp/pkg/sources/catalog"
)

// TestAllSplitsCoreAndSaaSWithoutOverlap guards the two invariants All()
// depends on: every entry has a non-empty category, and a name never
// appears twice (which would mean a core source and a SaaS connector
// claimed the same name).
func TestAllSplitsCoreAndSaaSWithoutOverlap(t *testing.T) {
	entries := catalog.All()
	if len(entries) == 0 {
		t.Fatal("catalog.All() returned no entries; is pkg/sources/all blank-imported?")
	}

	seen := make(map[string]catalog.Category, len(entries))
	core, saas := 0, 0
	for _, e := range entries {
		if prev, dup := seen[e.Name]; dup {
			t.Errorf("name %q registered twice: %s and %s", e.Name, prev, e.Category)
		}
		seen[e.Name] = e.Category
		switch e.Category {
		case catalog.CategoryCoreSource:
			core++
		case catalog.CategorySaaSConnector:
			saas++
		default:
			t.Errorf("entry %q has unknown category %q", e.Name, e.Category)
		}
	}
	if core == 0 {
		t.Error("catalog.All() reported zero core-source entries")
	}
	if saas == 0 {
		t.Error("catalog.All() reported zero saas-connector entries")
	}
}

// TestAllIsSortedByName pins the ordering contract callers (the `sources
// list` table, JSON, and names formats) rely on for stable output.
func TestAllIsSortedByName(t *testing.T) {
	entries := catalog.All()
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name > entries[i].Name {
			t.Fatalf("catalog.All() not sorted: %q before %q", entries[i-1].Name, entries[i].Name)
		}
	}
}
