// Command docsync regenerates docs/comparison.md's "Live re-measurement"
// section from bench/results/results.json (issue #299: keep the
// published comparison numbers true automatically, without hand-editing
// the doc on every tag push or competitor release).
//
// It deliberately does NOT touch §1-§8's hand-authored prose, audit
// trail, or per-file matrices below the marker — those were produced by
// an adversarial audit process (see docs/comparison.md's "Reproducing"
// section and bench/README.md) that this tool cannot reproduce from
// results.json's boolean hit/miss data alone, and fabricating that
// narrative for an arbitrary future measurement would be worse than
// leaving it as a dated snapshot. Only the clearly-delimited "Live
// re-measurement" block — headline recall counts and tool versions,
// both mechanically derived from results.json — is rewritten.
//
// Usage: go run ./bench/docsync -results bench/results/results.json \
//
//	-doc docs/comparison.md -trigger "tag v1.2.3"
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	startMarker = "<!-- BENCH:AUTO:START -->"
	endMarker   = "<!-- BENCH:AUTO:END -->"
)

// resultsBundle mirrors bench/harness's resultsBundle (report.go). Not
// imported directly — bench/harness is a separate `package main`, and
// duplicating this narrow read-only shape is cheaper than restructuring
// either program into an importable package for one shared type; see
// bench/CONTRIBUTING.md's "keep it minimal" style note.
type resultsBundle struct {
	GeneratedAt string            `json:"generated_at"`
	Versions    map[string]string `json:"versions"`
	Corpora     []corpusReport    `json:"corpora"`
}

type corpusReport struct {
	Corpus string   `json:"corpus"`
	Tools  []recall `json:"recall"`
}

type recall struct {
	Tool  string `json:"Tool"`
	Hit   int    `json:"Hit"`
	Total int    `json:"Total"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "docsync:", err)
		os.Exit(1)
	}
}

func run() error {
	resultsPath := flag.String("results", "bench/results/results.json", "path to bench/harness's results.json")
	docPath := flag.String("doc", "docs/comparison.md", "path to the doc to update in place")
	trigger := flag.String("trigger", "manual run", "human-readable reason this run fired, e.g. \"tag push v1.2.3\" or \"trufflehog release v3.96.0 detected\"")
	flag.Parse()

	raw, err := os.ReadFile(*resultsPath)
	if err != nil {
		return fmt.Errorf("read %s (run `make bench` first): %w", *resultsPath, err)
	}
	var bundle resultsBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("parse %s: %w", *resultsPath, err)
	}

	docRaw, err := os.ReadFile(*docPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", *docPath, err)
	}
	updated, err := spliceBlock(string(docRaw), renderBlock(bundle, *trigger))
	if err != nil {
		return fmt.Errorf("%s: %w", *docPath, err)
	}
	if updated == string(docRaw) {
		fmt.Println("docsync: no change (numbers already current)")
		return nil
	}
	if err := os.WriteFile(*docPath, []byte(updated), 0o644); err != nil {
		return err
	}
	fmt.Printf("docsync: updated %s\n", *docPath)
	return nil
}

// spliceBlock replaces the text strictly between startMarker and
// endMarker with block, keeping the markers themselves. Errors rather
// than silently no-op'ing if the markers are missing — a doc edit that
// accidentally drops a marker should fail CI loudly, not stop updating
// forever.
func spliceBlock(doc, block string) (string, error) {
	startIdx := strings.Index(doc, startMarker)
	if startIdx == -1 {
		return "", fmt.Errorf("marker %q not found", startMarker)
	}
	contentStart := startIdx + len(startMarker)
	endIdx := strings.Index(doc[contentStart:], endMarker)
	if endIdx == -1 {
		return "", fmt.Errorf("marker %q not found after %q", endMarker, startMarker)
	}
	endIdx += contentStart
	return doc[:contentStart] + "\n" + block + doc[endIdx:], nil
}

func renderBlock(bundle resultsBundle, trigger string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Generated:** %s · **Trigger:** %s · **Full run:** `bench/results/results.json` / `bench/results/results.md` (uploaded as a workflow artifact)\n\n", bundle.GeneratedAt, trigger)

	b.WriteString("| Tool | Version measured |\n|---|---|\n")
	for _, tool := range []string{"pleno-dlp", "trufflehog", "gitleaks"} {
		v := bundle.Versions[tool]
		if v == "" {
			v = "(not run)"
		}
		fmt.Fprintf(&b, "| %s | %s |\n", tool, v)
	}
	b.WriteString("\n")

	b.WriteString("| Corpus | Tool | Detected | Total | Recall |\n|---|---|---:|---:|---:|\n")
	for _, corpus := range bundle.Corpora {
		for _, rec := range corpus.Tools {
			pct := 0.0
			if rec.Total > 0 {
				pct = 100 * float64(rec.Hit) / float64(rec.Total)
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %.0f%% |\n", corpus.Corpus, rec.Tool, rec.Hit, rec.Total, pct)
		}
	}
	b.WriteString("\n")
	b.WriteString("This block is regenerated mechanically by `go run ./bench/docsync` from the JSON above — it does not touch §1-§8's hand-audited prose below, which remains a dated snapshot (see \"Reproducing\").\n")
	return b.String()
}
