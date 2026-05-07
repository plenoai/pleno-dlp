package filesystem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultExcludes_PrunesNodeModulesAndDotGit(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "src/app.go", "package main")
	mustWrite(t, dir, "node_modules/leak.txt", "AKIAIOSFODNN7EXAMPLE")
	mustWrite(t, dir, ".git/HEAD", "ref: refs/heads/main")
	mustWrite(t, dir, "vendor/lib.go", "//noisy")

	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk (only src/app.go); got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "src/app.go") &&
		!strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "src\\app.go") {
		t.Fatalf("unexpected file: %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestDisableDefaultExcludes_ScansEverything(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "src/app.go", "package main")
	mustWrite(t, dir, "node_modules/leak.txt", "AKIAIOSFODNN7EXAMPLE")

	s := &Source{}
	mustInit(t, s, Config{
		Paths:                  []string{dir},
		DisableDefaultExcludes: true,
	})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 chunks (src + node_modules); got %d", len(got))
	}
}

func TestExclude_GlobMatchesBasename(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "secrets.env", "AKIA...")
	mustWrite(t, dir, "config.yaml", "foo: bar")

	s := &Source{}
	mustInit(t, s, Config{
		Paths:   []string{dir},
		Exclude: []string{"*.env"},
	})

	got, _ := drain(t, s, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 chunk; got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "config.yaml") {
		t.Fatalf("expected config.yaml; got %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestInclude_OnlyMatchesIncluded(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "main.go", "package main")
	mustWrite(t, dir, "main.py", "x = 1")
	mustWrite(t, dir, "README.md", "# hi")

	s := &Source{}
	mustInit(t, s, Config{
		Paths:   []string{dir},
		Include: []string{"*.go"},
	})

	got, _ := drain(t, s, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 chunk; got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "main.go") {
		t.Fatalf("expected main.go; got %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestExcludeWinsOverInclude(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "main.go", "package main")
	mustWrite(t, dir, "main_test.go", "package main // test")

	s := &Source{}
	mustInit(t, s, Config{
		Paths:   []string{dir},
		Include: []string{"*.go"},
		Exclude: []string{"*_test.go"},
	})

	got, _ := drain(t, s, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 chunk (main.go only); got %d", len(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "main.go") ||
		strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "main_test.go") {
		t.Fatalf("expected main.go (not test); got %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

func TestInit_RejectsBadGlob(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "x.txt", "x")
	s := &Source{}
	cfg := Config{Paths: []string{dir}, Exclude: []string{"["}}
	raw, _ := jsonMarshal(cfg)
	err := s.Init(t.Context(), "test", 0, 0, false, raw, 1)
	if err == nil {
		t.Fatal("expected init error on malformed glob")
	}
}

// mustWrite creates parent dirs and writes content. Centralised so the
// exclusion tests stay focused on assertions rather than fixture setup.
func mustWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// jsonMarshal is an alias used by TestInit_RejectsBadGlob to keep the
// test focused on the assertion. Inlining encoding/json there would
// double the noise-to-signal ratio.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
