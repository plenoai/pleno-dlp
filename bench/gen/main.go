// Command gen writes the dlp-bench synthetic recall corpus (see
// bench/README.md and docs/comparison.md §2) to disk: one file per
// credential type, plus a labels.json ground-truth manifest the harness
// (bench/harness) and any third party reads instead of re-deriving.
//
// The corpus is intentionally NOT committed to the repo — every file
// contains a format-valid fake credential, and committing them would
// trip GitHub push protection and every secret scanner in CI on sight
// (this is the same reason docs/comparison.md's own §2 corpus was never
// committed). `make bench` runs this generator first; that is the
// reproduction path a third party follows.
//
// Usage:
//
//	go run ./bench/gen -out bench/fixtures/synthetic/generated
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/bench/labels"
)

func main() {
	out := flag.String("out", "bench/fixtures/synthetic/generated", "output directory for generated fixtures (scanned as-is by the 3 tools — must contain nothing but fixtures)")
	labelsFlag := flag.String("labels", "", "path for labels.json (default: sibling of -out, NOT inside it — a manifest inside the scanned dir is itself scannable text and pollutes recall, as pagerduty's bare-token regex found during development)")
	seed := flag.Uint64("seed", 42, "PRNG seed (fixed default keeps the corpus reproducible)")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	labelsPath := *labelsFlag
	if labelsPath == "" {
		labelsPath = filepath.Join(filepath.Dir(filepath.Clean(*out)), "labels.json")
	}

	rng := newRNG(*seed)
	entries := make([]labels.Entry, 0, len(fixtures))
	for _, fx := range fixtures {
		name := fx.Slug + ".txt"
		content := fx.Render(rng)
		if err := os.WriteFile(filepath.Join(*out, name), []byte(content), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		entries = append(entries, labels.Entry{
			Slug: fx.Slug, File: name, Detector: fx.Detector.String(),
			KnownMiss: knownMisses[fx.Slug],
		})
	}

	buf, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(labelsPath, buf, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Printf("gen: wrote %d fixtures to %s, labels to %s\n", len(fixtures), *out, labelsPath)
}
