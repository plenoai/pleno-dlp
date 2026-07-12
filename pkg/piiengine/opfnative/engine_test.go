//go:build opf_native

package opfnative

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDevice(t *testing.T) {
	cases := map[string]string{
		"":     platformAutoDevice,
		"auto": platformAutoDevice,
		"AUTO": platformAutoDevice,
		"mps":  "gpu",
		"MPS":  "gpu",
		"cpu":  "cpu",
		"cuda": "cuda",
		"gpu":  "gpu",
	}
	for in, want := range cases {
		if got := resolveDevice(in); got != want {
			t.Errorf("resolveDevice(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSubstr(t *testing.T) {
	const s = "hello@example.com"
	if got := substr(s, 0, 5); got != "hello" {
		t.Errorf("substr in-range = %q", got)
	}
	// Out-of-range / inverted spans must not panic; they yield "".
	for _, c := range []struct{ start, end int }{{-1, 3}, {0, len(s) + 1}, {5, 2}} {
		if got := substr(s, c.start, c.end); got != "" {
			t.Errorf("substr(%d,%d) = %q, want \"\"", c.start, c.end, got)
		}
	}
}

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

func TestNew_EmptyModelPath(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrEmptyModelPath) {
		t.Errorf("New empty path err = %v, want ErrEmptyModelPath", err)
	}
}

func TestSetDefault(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })
	if Default() != nil {
		t.Fatal("Default() must start nil")
	}
	e := &Engine{}
	SetDefault(e)
	if Default() != e {
		t.Error("Default() must return the SetDefault'd engine")
	}
	SetDefault(nil)
	if Default() != nil {
		t.Error("Default() must clear to nil")
	}
}

// TestEngine_Integration exercises the real cgo path (pf_load / pf_classify /
// pf_free) against an actual GGUF. Guarded by PLENO_OPF_GGUF so the default
// -tags opf_native test run stays weight-free; CI/local sets it to a
// checksum-verified GGUF to confirm end-to-end inference.
func TestEngine_Integration(t *testing.T) {
	path := os.Getenv("PLENO_OPF_GGUF")
	if path == "" {
		t.Skip("set PLENO_OPF_GGUF to a privacy-filter GGUF to run the native inference integration test")
	}
	eng, err := New(Config{ModelPath: path, Device: os.Getenv("PLENO_OPF_DEVICE")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	const text = "Contact John Smith at john.smith@example.com or +1-202-555-0143."
	fs, err := eng.Analyze(context.Background(), text)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected at least one PII finding")
	}
	for _, f := range fs {
		if f.EntityType == "" {
			t.Errorf("finding missing EntityType: %+v", f)
		}
		if f.BIOESTag != "" {
			t.Errorf("BIOESTag must be empty (libpf resolves spans): %q", f.BIOESTag)
		}
		if f.Start < 0 || f.End > len(text) || f.Start > f.End {
			t.Errorf("finding span out of range: %+v", f)
		}
		if want := text[f.Start:f.End]; f.Text != want {
			t.Errorf("Text %q != byte span %q", f.Text, want)
		}
		t.Logf("finding: %s %q score=%.3f [%d:%d]", f.EntityType, f.Text, f.Score, f.Start, f.End)
	}

	// Close is idempotent; a second call must not double-free.
	if err := eng.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Analyze after Close is a clean error, not a crash.
	if _, err := eng.Analyze(context.Background(), text); !errors.Is(err, ErrClosed) {
		t.Errorf("Analyze after Close err = %v, want ErrClosed", err)
	}
}
