// Package catalog unifies pkg/sources' core-source registry and
// pkg/connectors' SaaS-connector registry into one enumerable list, so
// `pleno-dlp sources list` and doc counts derive from what is actually
// registered instead of hand-typed prose.
//
// All() requires the caller's process to have already triggered every
// provider's init() (the CLI does this via a blank import of
// pkg/sources/all in main.go), exactly like pkg/detectors.All() requires
// pkg/detectors/all.
package catalog

import (
	"sort"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Category distinguishes how an entry reaches the engine.
type Category string

const (
	CategoryCoreSource    Category = "core-source"
	CategorySaaSConnector Category = "saas-connector"
)

// Entry is one row in the unified catalog.
type Entry struct {
	Name     string
	Type     sources.SourceType
	Category Category
}

// All enumerates every registered core source and SaaS connector, sorted by
// name. Core sources come from sources.Registered(); SaaS connectors come
// from connectors.Names(). Neither list is hand-maintained, so this cannot
// drift from what New()/AsSource() would actually resolve.
func All() []Entry {
	names := connectors.Names()
	out := make([]Entry, 0, len(names)+8)
	for _, t := range sources.Registered() {
		out = append(out, Entry{Name: t.String(), Type: t, Category: CategoryCoreSource})
	}
	for _, name := range names {
		c, ok := connectors.Get(name)
		if !ok {
			continue
		}
		out = append(out, Entry{Name: name, Type: c.SourceType, Category: CategorySaaSConnector})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
