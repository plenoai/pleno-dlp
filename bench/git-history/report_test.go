package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/bench/git-history/fixture"
)

func TestNewResultGatesAndArtifactsOmitCanary(t *testing.T) {
	meta := testMetadata()
	meta.Head = "head"
	meta.Inventory = fixture.ExpectedInventory(fixture.Spec{Commits: 2, Files: 2})
	opts := options{commits: 2, files: 2, window: 1, warmups: 1, runs: 2}
	source := sourceResult{TailEarlyRatio: 0.90}
	tools := []toolResult{
		{Name: "pleno-dlp", MedianSeconds: 9, SampleIterations: []int{1}, SampleWallSeconds: []float64{9}},
		{Name: "trufflehog", MedianSeconds: 10, SampleIterations: []int{1}, SampleWallSeconds: []float64{10}},
	}
	result := newResult(opts, meta, source, tools)
	if !result.Gates.Pass || result.Gates.PlenoToTrufflehogRatio != 0.90 {
		t.Fatalf("gates=%+v", result.Gates)
	}
	if result.Fixture.Files != 2 {
		t.Fatalf("fixture files=%d want=2", result.Fixture.Files)
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "result.json")
	markdownPath := filepath.Join(dir, "result.md")
	if err := writeResults(jsonPath, markdownPath, result); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{jsonPath, markdownPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), meta.Canary) {
			t.Fatalf("%s contains the canary value", path)
		}
	}
}
