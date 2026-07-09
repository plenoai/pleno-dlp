// Package main implements the dlp-bench re-run harness (issue #298):
// it runs pleno-dlp, trufflehog, and gitleaks against the same corpus
// and reports recall per tool. See bench/README.md for the full
// reproduction story and bench/CONTRIBUTING.md for how to extend it.
package main

// finding is the common shape every tool's JSON output is parsed into.
// File is normalized to an absolute path so cross-tool comparison
// against a ground-truth file list is exact regardless of each tool's
// own path rendering.
type finding struct {
	Tool string // "pleno-dlp" | "trufflehog" | "gitleaks"
	File string
	// Name is the tool's own label for what fired: pleno-dlp's
	// detector name, trufflehog's DetectorName, gitleaks' RuleID. Kept
	// for the results table's "matched as" column — recall itself is
	// computed on File presence only (docs/comparison.md §2's own
	// methodology: "a type counts as detected iff the tool emitted at
	// least one secret finding in that type's file").
	Name string
}
