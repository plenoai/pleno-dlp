package cmd

import (
	"bytes"
	"strings"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

func TestCompletion_Bash(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"completion", "bash"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("completion bash: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"# bash completion", "pleno-dlp", "scan", "detectors"} {
		if !strings.Contains(got, want) {
			t.Errorf("bash completion missing %q (sample shown to ops would be incomplete):\n%s", want, got[:min(400, len(got))])
		}
	}
}

func TestCompletion_Zsh(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"completion", "zsh"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("completion zsh: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "compdef") && !strings.Contains(got, "_pleno-dlp") {
		t.Errorf("zsh completion missing compdef header in:\n%s", got[:min(400, len(got))])
	}
}

func TestCompletion_Fish(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"completion", "fish"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("completion fish: %v", err)
	}
	if !strings.Contains(out.String(), "complete -c pleno-dlp") {
		t.Errorf("fish completion missing the complete -c shape")
	}
}

func TestCompletion_PowerShell(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"completion", "powershell"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("completion powershell: %v", err)
	}
	if !strings.Contains(out.String(), "Register-ArgumentCompleter") {
		t.Errorf("powershell completion missing Register-ArgumentCompleter")
	}
}

func TestCompletion_RejectsBadShell(t *testing.T) {
	resetCommandFlags(t)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"completion", "csh"})
	if err := Root.Execute(); err == nil {
		t.Errorf("expected error on unknown shell")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
