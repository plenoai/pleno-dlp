//go:build opf_native

package opfnative

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveModelPath_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "weights.gguf")
	if err := os.WriteFile(p, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveModelPath(context.Background(), "", p, nil)
	if err != nil {
		t.Fatalf("explicit path: %v", err)
	}
	if got != p {
		t.Errorf("explicit path = %q, want %q", got, p)
	}
	// A missing explicit path is a hard error, never a silent download.
	if _, err := ResolveModelPath(context.Background(), "", filepath.Join(dir, "nope.gguf"), nil); err == nil {
		t.Error("missing explicit path must error")
	}
}

func TestResolveModelPath_UnknownVariant(t *testing.T) {
	_, err := ResolveModelPath(context.Background(), "q4", "", nil)
	if !errors.Is(err, ErrUnknownVariant) {
		t.Errorf("unknown variant err = %v, want ErrUnknownVariant", err)
	}
}

func TestCachedModelPathDoesNotCreateOrDownload(t *testing.T) {
	dir := t.TempDir()
	path, available, err := cachedModelPath(dir, "q8", modelVariants["q8"])
	if err != nil || available {
		t.Fatalf("empty cache = %q, %v, %v; want unavailable", path, available, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cache probe changed the cache directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, modelCacheFilename("q8", modelVariants["q8"])), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, available, err = cachedModelPath(dir, "q8", modelVariants["q8"])
	if err != nil || !available || path == "" {
		t.Fatalf("populated cache = %q, %v, %v; want available model", path, available, err)
	}
}

func TestCachedModelPathRejectsNonRegularEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, modelCacheFilename("q8", modelVariants["q8"])), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, available, err := cachedModelPath(dir, "q8", modelVariants["q8"]); err == nil || available {
		t.Fatalf("directory cache entry = available %v, err %v; want rejection", available, err)
	}
}
