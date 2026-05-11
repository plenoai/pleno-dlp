package filesystem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
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

// TestDefaultExcludes_PrunesLockfiles checks that high-FP-noise lockfile
// basenames (package-lock.json, go.sum, …) are skipped by default. These
// files routinely contain dozens of sha512 / integrity hashes that the
// generic detector cannot distinguish from real high-entropy secrets, so
// they're the single largest source of FP findings in real scans.
func TestDefaultExcludes_PrunesLockfiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "src/app.go", "package main")
	// AKIA-shaped bait inside a lockfile. The generic detector would
	// otherwise gladly emit on this if the file were scanned.
	mustWrite(t, dir, "package-lock.json", `{"integrity": "sha512-AKIAIOSFODNN7EXAMPLE"}`)
	mustWrite(t, dir, "yarn.lock", "AKIAIOSFODNN7EXAMPLE")
	mustWrite(t, dir, "go.sum", "github.com/foo v1.0.0 h1:AKIAIOSFODNN7EXAMPLE=")
	mustWrite(t, dir, "Gemfile.lock", "  remote: AKIAIOSFODNN7EXAMPLE")

	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk (only src/app.go); got %d:\n%s", len(got), chunkPaths(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "src/app.go") &&
		!strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "src\\app.go") {
		t.Fatalf("unexpected file: %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

// TestDisableDefaultExcludes_ScansLockfiles ensures the opt-out switch
// genuinely lets through the same lockfiles the default-on path skips.
// Without this assertion, a typo in commonExcludes ("Gemfile.locked")
// could silently strip the exclusion without any test ever noticing.
func TestDisableDefaultExcludes_ScansLockfiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "src/app.go", "package main")
	mustWrite(t, dir, "package-lock.json", `{}`)
	mustWrite(t, dir, "yarn.lock", "")

	s := &Source{}
	mustInit(t, s, Config{
		Paths:                  []string{dir},
		DisableDefaultExcludes: true,
	})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	// 3 = src/app.go + package-lock.json + yarn.lock.
	if len(got) != 3 {
		t.Fatalf("want 3 chunks with default excludes disabled; got %d:\n%s", len(got), chunkPaths(got))
	}
}

// TestDefaultExcludes_PrunesMinifiedBundles checks the glob path of
// commonExcludes — *.min.js, *.map, and *.bundle.js are filtered as
// basenames, while plain app.js sails through. Sourcemap and minifier
// output dominate the FP rate on web repos because both are dense
// streams of base64-encoded names with no surrounding prose for the
// generic detector to use as context.
func TestDefaultExcludes_PrunesMinifiedBundles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "app.js", "console.log('hi')")
	mustWrite(t, dir, "app.min.js", "var a=b;c=d;AKIAIOSFODNN7EXAMPLE;")
	mustWrite(t, dir, "app.bundle.js", "AKIAIOSFODNN7EXAMPLE")
	mustWrite(t, dir, "app.js.map", `{"mappings":"AAAA;AAAA"}`)
	mustWrite(t, dir, "style.min.css", ".a{color:#fff}")

	s := &Source{}
	mustInit(t, s, Config{Paths: []string{dir}})

	got, err := drain(t, s, 5*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk (only app.js); got %d:\n%s", len(got), chunkPaths(got))
	}
	if !strings.HasSuffix(got[0].SourceMetadata.Filesystem.Path, "app.js") {
		t.Fatalf("expected app.js; got %s", got[0].SourceMetadata.Filesystem.Path)
	}
}

// chunkPaths formats observed chunk paths for diagnostic test output —
// when the count assertion above fires, the operator wants to see which
// extra file survived the exclude, not "want 1, got 3".
func chunkPaths(chunks []*sources.Chunk) string {
	var lines []string
	for _, c := range chunks {
		if c.SourceMetadata.Filesystem != nil {
			lines = append(lines, "  - "+c.SourceMetadata.Filesystem.Path)
		}
	}
	return strings.Join(lines, "\n")
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
