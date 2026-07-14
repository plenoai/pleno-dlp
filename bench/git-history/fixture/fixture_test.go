package fixture

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

func TestGenerateIsDeterministicAndExact(t *testing.T) {
	spec := Spec{Commits: 12, Files: 4}
	first, err := Generate(context.Background(), filepath.Join(t.TempDir(), "first.git"), spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(context.Background(), filepath.Join(t.TempDir(), "second.git"), spec)
	if err != nil {
		t.Fatal(err)
	}
	if first.Head != second.Head || first.CanaryCommit != second.CanaryCommit {
		t.Fatalf("fixture hashes differ: first=%s/%s second=%s/%s", first.Head, first.CanaryCommit, second.Head, second.CanaryCommit)
	}
	want := ExpectedInventory(spec)
	if first.Inventory.Blobs != want.Blobs || first.Inventory.Commits != want.Commits || first.Inventory.Trees != want.Trees || first.Inventory.Total != want.Total {
		t.Fatalf("inventory=%+v want=%+v", first.Inventory, want)
	}
	if engine.IsPlaceholder([]byte(first.Canary)) {
		t.Fatal("canary is a placeholder")
	}
	if !strings.HasPrefix(first.Canary, "ghp_") || len(first.Canary) != 40 {
		t.Fatalf("invalid canary shape: prefix=%t length=%d", strings.HasPrefix(first.Canary, "ghp_"), len(first.Canary))
	}

	out, err := exec.Command("git", "-C", first.Repo, "show", first.CanaryCommit+":"+first.CanaryPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), first.Canary) {
		t.Fatal("canary commit does not contain the generated canary")
	}
}

func TestGenerateRejectsExistingPath(t *testing.T) {
	path := t.TempDir()
	if _, err := Generate(context.Background(), path, Spec{Commits: 1, Files: 1}); err == nil {
		t.Fatal("existing fixture path accepted")
	}
}

func TestGenerateForcesSHA1(t *testing.T) {
	t.Setenv("GIT_DEFAULT_HASH", "sha256")
	meta, err := Generate(context.Background(), filepath.Join(t.TempDir(), "fixture.git"), Spec{Commits: 8, Files: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Head) != 40 {
		t.Fatalf("head length=%d want=40", len(meta.Head))
	}
}
