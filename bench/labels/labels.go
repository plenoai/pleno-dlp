// Package labels defines the ground-truth manifest schema shared by
// bench/gen (writer) and bench/harness (reader), so the two never drift
// on field names independently.
package labels

// Entry is one ground-truth record: File contains exactly one synthetic
// secret of Detector's pleno-dlp type. It intentionally does not record
// a per-tool expected outcome — see bench/gen/spec.go's fixture doc
// comment for why that would go stale.
type Entry struct {
	Slug     string `json:"slug"`
	File     string `json:"file"`
	Detector string `json:"pleno_dlp_detector"`
	// KnownMiss, when non-empty, is a maintainer-attested current
	// pleno-dlp false negative on this fixture and why (see
	// bench/gen/spec.go's knownMisses) — this is what lets the
	// harness's results table report pleno-dlp's own losses, not only
	// its wins, per issue #298.
	KnownMiss string `json:"known_miss,omitempty"`
}
