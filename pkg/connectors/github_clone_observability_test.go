package connectors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryBytesReportsCompleteLogicalFileSizes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"config":              "cfg",
		"objects/pack-a.pack": "pack bytes",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, elapsed, err := measureDirectoryBytes(context.Background(), root)
	if err != nil {
		t.Fatalf("measureDirectoryBytes: %v", err)
	}
	if want := int64(len("cfg") + len("pack bytes")); got != want {
		t.Fatalf("directory bytes = %d, want %d", got, want)
	}
	if elapsed < 0 {
		t.Fatalf("measurement duration = %s, want non-negative", elapsed)
	}
	if label := cloneDirectoryBytesLabel(got, nil); label != "13" {
		t.Fatalf("clone byte label = %q, want 13", label)
	}
}

func TestDirectoryBytesMeasurementHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "clone.pack"), []byte("pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, elapsed, err := measureDirectoryBytes(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("measureDirectoryBytes error = %v, want context.Canceled", err)
	}
	if got != 0 {
		t.Fatalf("cancelled measurement returned partial bytes %d, want zero sentinel", got)
	}
	if elapsed < 0 {
		t.Fatalf("measurement duration = %s, want non-negative", elapsed)
	}
	if label := cloneDirectoryBytesLabel(got, err); label != "unavailable" {
		t.Fatalf("cancelled measurement label = %q, want unavailable", label)
	}
}

func TestDirectoryBytesMeasurementFailureIsUnavailable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	got, elapsed, err := measureDirectoryBytes(context.Background(), root)
	if err == nil {
		t.Fatal("missing clone directory measurement succeeded")
	}
	if got != 0 {
		t.Fatalf("failed measurement returned partial bytes %d, want zero sentinel", got)
	}
	if elapsed < 0 {
		t.Fatalf("measurement duration = %s, want non-negative", elapsed)
	}
	if label := cloneDirectoryBytesLabel(got, err); label != "unavailable" {
		t.Fatalf("failed measurement label = %q, want unavailable", label)
	}
}
