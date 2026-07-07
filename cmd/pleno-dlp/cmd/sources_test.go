package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

func TestSourcesList_Table(t *testing.T) {
	t.Cleanup(func() { sourcesListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"sources", "list"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("sources list: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"SOURCE", "CATEGORY", "CLI-WIRED", "filesystem", "github", "elasticsearch", "source(s) registered"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q in:\n%s", want, got)
		}
	}
}

func TestSourcesList_JSON(t *testing.T) {
	t.Cleanup(func() { sourcesListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"sources", "list", "--format", "json"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("sources list --format json: %v\noutput:\n%s", err, out.String())
	}
	var rows []sourceRecord
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decode json: %v\noutput:\n%s", err, out.String())
	}
	if len(rows) == 0 {
		t.Fatal("sources list --format json returned zero rows")
	}

	byName := make(map[string]sourceRecord, len(rows))
	for _, r := range rows {
		byName[r.Name] = r
	}

	fs, ok := byName["filesystem"]
	if !ok || fs.Category != "core-source" || !fs.CLIWired {
		t.Errorf("filesystem row = %+v, want core-source, cli_wired=true", fs)
	}
	gh, ok := byName["github"]
	if !ok || gh.Category != "saas-connector" || !gh.CLIWired {
		t.Errorf("github row = %+v, want saas-connector, cli_wired=true", gh)
	}
	es, ok := byName["elasticsearch"]
	if !ok || es.Category != "saas-connector" || es.CLIWired {
		t.Errorf("elasticsearch row = %+v, want saas-connector, cli_wired=false (planned, no scan subcommand)", es)
	}
}

func TestSourcesList_Names(t *testing.T) {
	t.Cleanup(func() { sourcesListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"sources", "list", "--format", "names"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("sources list --format names: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "filesystem") {
		t.Errorf("names output missing %q in:\n%s", "filesystem", out.String())
	}
}

func TestSourcesList_RejectsBadFormat(t *testing.T) {
	t.Cleanup(func() { sourcesListOpts.format = "table" })

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"sources", "list", "--format", "yaml"})
	if err := Root.Execute(); err == nil {
		t.Fatal("expected error for unknown --format, got nil")
	}
}
