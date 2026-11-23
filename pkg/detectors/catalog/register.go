//go:build !kingfisher_nocatalog

package catalog

import "github.com/plenoai/pleno-dlp/pkg/detectors"

// The kingfisher_nocatalog build tag leaves the catalog unregistered so
// scripts/kingfisher-catalog.py can measure native detector coverage and
// import only the rules no native detector matches.
func init() {
	build()
	for _, h := range hostScanners {
		detectors.Register(h)
	}
	for t, fs := range extensions {
		detectors.RegisterFormats(t, fs...)
	}
}
