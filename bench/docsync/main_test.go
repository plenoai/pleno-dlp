package main

import (
	"strings"
	"testing"
)

func TestSpliceBlock(t *testing.T) {
	doc := "before\n<!-- BENCH:AUTO:START -->\nstale content\n<!-- BENCH:AUTO:END -->\nafter\n"
	got, err := spliceBlock(doc, "fresh content\n")
	if err != nil {
		t.Fatalf("spliceBlock: %v", err)
	}
	if !strings.Contains(got, "fresh content") {
		t.Errorf("expected fresh content in output, got %q", got)
	}
	if strings.Contains(got, "stale content") {
		t.Errorf("stale content should have been replaced, got %q", got)
	}
	if !strings.HasPrefix(got, "before\n"+startMarker) {
		t.Errorf("expected content before the start marker to survive untouched, got %q", got)
	}
	if !strings.HasSuffix(got, endMarker+"\nafter\n") {
		t.Errorf("expected content after the end marker to survive untouched, got %q", got)
	}
}

func TestSpliceBlock_MissingMarkers(t *testing.T) {
	if _, err := spliceBlock("no markers here", "x"); err == nil {
		t.Fatal("expected error when start marker is missing")
	}
	if _, err := spliceBlock(startMarker+"\nno end marker", "x"); err == nil {
		t.Fatal("expected error when end marker is missing")
	}
}

func TestRenderBlock(t *testing.T) {
	bundle := resultsBundle{
		GeneratedAt: "2026-07-10T00:00:00Z",
		Versions:    map[string]string{"pleno-dlp": "v1.2.3", "trufflehog": "3.95.5", "gitleaks": "8.30.1"},
		Corpora: []corpusReport{
			{Corpus: "synthetic", Tools: []recall{{Tool: "pleno-dlp", Hit: 46, Total: 50}}},
		},
	}
	out := renderBlock(bundle, "tag push v1.2.3")
	for _, want := range []string{"v1.2.3", "tag push v1.2.3", "46", "50", "92%"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderBlock output missing %q:\n%s", want, out)
		}
	}
}
