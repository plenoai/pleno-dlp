package main

import (
	"path/filepath"
	"sort"
)

// fileRow is one ground-truth row's live outcome across the three
// tools — the unit the results table (report.go) renders one line per.
type fileRow struct {
	File string // basename, e.g. "aws-access-key-pair.txt"
	// Detected[tool] is true iff that tool emitted at least one finding
	// whose file matches. Matches docs/comparison.md §2's own
	// methodology: "a type counts as detected iff the tool emitted at
	// least one secret finding in that type's file."
	Detected map[string]bool
	// KnownMiss carries the ground-truth manifest's note forward so a
	// documented pleno-dlp loss reads as "known" rather than "new
	// regression" in the rendered table.
	KnownMiss string
}

// recall summarizes one tool's hits over a set of ground-truth files —
// the same shape whether the ground truth came from bench/gen's
// synthetic manifest or leaky-repo's own .leaky-meta/secrets.csv.
type recall struct {
	Tool   string
	Hit    int
	Total  int
	Misses []string // basenames the tool missed, always populated —
	// this IS the "own losses" requirement: never trimmed to hide a
	// tool's failures, pleno-dlp's included.
}

// tools is the fixed, ordered set of tools every recall table reports,
// so results.md renders in the same column order as
// docs/comparison.md.
var tools = []string{"pleno-dlp", "trufflehog", "gitleaks"}

// scoreFiles builds one fileRow per ground-truth file and the derived
// per-tool recall summary. findingsByTool maps tool name to every
// finding it emitted on the corpus; only the basename of finding.File
// is used for matching, since gitleaks/trufflehog/pleno-dlp each render
// paths differently (absolute vs. corpus-relative) but a synthetic
// corpus never has two files sharing a basename.
func scoreFiles(groundTruth []string, knownMiss map[string]string, findingsByTool map[string][]finding) ([]fileRow, []recall) {
	hitSets := make(map[string]map[string]bool, len(tools))
	for _, tool := range tools {
		set := make(map[string]bool)
		for _, f := range findingsByTool[tool] {
			set[filepath.Base(f.File)] = true
		}
		hitSets[tool] = set
	}

	sorted := append([]string(nil), groundTruth...)
	sort.Strings(sorted)

	rows := make([]fileRow, 0, len(sorted))
	recalls := make(map[string]*recall, len(tools))
	for _, tool := range tools {
		recalls[tool] = &recall{Tool: tool, Total: len(sorted)}
	}

	for _, file := range sorted {
		row := fileRow{File: file, Detected: make(map[string]bool, len(tools)), KnownMiss: knownMiss[file]}
		for _, tool := range tools {
			hit := hitSets[tool][file]
			row.Detected[tool] = hit
			if hit {
				recalls[tool].Hit++
			} else {
				recalls[tool].Misses = append(recalls[tool].Misses, file)
			}
		}
		rows = append(rows, row)
	}

	out := make([]recall, 0, len(tools))
	for _, tool := range tools {
		out = append(out, *recalls[tool])
	}
	return rows, out
}
