package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

func TestDetectorsList_Table(t *testing.T) {
	t.Cleanup(func() { detectorsListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"detectors", "list"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("detectors list: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"DETECTOR", "VERIFIES", "KEYWORDS", "AWS", "GitHub", "OpenAI", "GenericHighEntropy", "detector(s) registered"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q in:\n%s", want, got)
		}
	}
}

func TestDetectorsList_JSON(t *testing.T) {
	t.Cleanup(func() { detectorsListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"detectors", "list", "--format", "json"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("detectors list --format json: %v\noutput:\n%s", err, out.String())
	}
	var rows []detectorRecord
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("expected JSON array, got: %v\noutput:\n%s", err, out.String())
	}
	if len(rows) < 50 {
		t.Errorf("expected at least 50 detectors registered, got %d", len(rows))
	}
	// Sort stability: type names must come back ascending.
	for i := 1; i < len(rows); i++ {
		if rows[i].Type < rows[i-1].Type {
			t.Errorf("detector list not sorted: %q < %q at index %d", rows[i].Type, rows[i-1].Type, i)
		}
	}
	// Spot-check the verifies bit on a known-verified detector.
	for _, r := range rows {
		if r.Type == "AWS" {
			if !r.Verifies {
				t.Errorf("AWS detector should report verifies=true")
			}
			if len(r.Keywords) == 0 {
				t.Errorf("AWS detector should declare keywords")
			}
			return
		}
	}
	t.Errorf("AWS detector missing from list")
}

func TestDetectorsList_Names(t *testing.T) {
	t.Cleanup(func() { detectorsListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"detectors", "list", "--format", "names"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("detectors list --format names: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 50 {
		t.Errorf("expected >= 50 lines, got %d", len(lines))
	}
}

func TestDetectorsList_RejectsBadFormat(t *testing.T) {
	t.Cleanup(func() { detectorsListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"detectors", "list", "--format", "yaml"})
	if err := Root.Execute(); err == nil {
		t.Errorf("expected error on unknown format")
	}
}
