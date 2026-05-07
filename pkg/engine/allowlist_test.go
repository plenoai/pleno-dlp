package engine

import (
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestLoadAllowlist_ValidatesEmptyEntry(t *testing.T) {
	_, err := LoadAllowlist(strings.NewReader(`{"entries":[{}]}`))
	if err == nil {
		t.Fatal("expected error: empty entry must be rejected (would mute every finding)")
	}
}

func TestLoadAllowlist_RejectsBadRegex(t *testing.T) {
	_, err := LoadAllowlist(strings.NewReader(`{"entries":[{"raw_regex":"["}]}`))
	if err == nil {
		t.Fatal("expected regex compile error")
	}
}

func TestLoadAllowlist_AcceptsEmptyInput(t *testing.T) {
	a, err := LoadAllowlist(strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty input must be ok, got %v", err)
	}
	if a != nil {
		t.Fatalf("expected nil allowlist on empty input")
	}
}

func TestMatch_DetectorAndRaw(t *testing.T) {
	a, err := LoadAllowlist(strings.NewReader(`{"entries":[
		{"detector":"AWS","raw":"AKIAIOSFODNN7EXAMPLE","reason":"trufflehog dummy"}
	]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	hit := Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{Raw: []byte("AKIAIOSFODNN7EXAMPLE")},
		Chunk:    &sources.Chunk{},
	}
	if !a.Match(hit) {
		t.Errorf("expected match on AWS dummy")
	}
	miss := hit
	miss.Result.Raw = []byte("AKIAIOSFODNN7DIFFERE")
	if a.Match(miss) {
		t.Errorf("different raw must not match")
	}
}

func TestMatch_RawRegex(t *testing.T) {
	a, err := LoadAllowlist(strings.NewReader(`{"entries":[
		{"raw_regex":"^AKIA.*EXAMPLE$"}
	]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !a.Match(Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{Raw: []byte("AKIAIOSFODNN7EXAMPLE")},
		Chunk:    &sources.Chunk{},
	}) {
		t.Error("regex must match canonical AWS example")
	}
}

func TestMatch_PathBasenameAndFull(t *testing.T) {
	a, err := LoadAllowlist(strings.NewReader(`{"entries":[
		{"path":"*_test.go"},
		{"path":"fixtures/**/*.env"}
	]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	mk := func(path string) Finding {
		return Finding{
			Result: detectors.Result{Raw: []byte("x")},
			Chunk: &sources.Chunk{
				SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: path}},
			},
		}
	}
	if !a.Match(mk("/repo/foo_test.go")) {
		t.Error("basename glob *_test.go must match foo_test.go")
	}
	if !a.Match(mk("/repo/fixtures/sub/secret.env")) {
		t.Error("** glob must match nested .env")
	}
	if a.Match(mk("/repo/main.go")) {
		t.Error("non-test source must not match")
	}
}

func TestMatch_AndAcrossDimensions(t *testing.T) {
	a, err := LoadAllowlist(strings.NewReader(`{"entries":[
		{"detector":"AWS","path":"*.env"}
	]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	mk := func(det detectors.DetectorType, path string) Finding {
		return Finding{
			Detector: det,
			Result:   detectors.Result{Raw: []byte("x")},
			Chunk: &sources.Chunk{
				SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: path}},
			},
		}
	}
	if !a.Match(mk(detectors.AWS, "/repo/secrets.env")) {
		t.Error("AWS in .env must match (both conditions hold)")
	}
	if a.Match(mk(detectors.AWS, "/repo/secrets.go")) {
		t.Error("AWS in .go must NOT match (path mismatch)")
	}
	if a.Match(mk(detectors.OpenAI, "/repo/secrets.env")) {
		t.Error("OpenAI in .env must NOT match (detector mismatch)")
	}
}

func TestSink_SuppressesAndCounts(t *testing.T) {
	a, _ := LoadAllowlist(strings.NewReader(`{"entries":[{"raw":"AKIAIOSFODNN7EXAMPLE"}]}`))
	captured := &captureSink{}
	wrapped := NewAllowlist(a, captured)

	wrapped.Emit(Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{Raw: []byte("AKIAIOSFODNN7EXAMPLE")},
		Chunk:    &sources.Chunk{},
	})
	wrapped.Emit(Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{Raw: []byte("AKIAIOSFODNN7REAL")},
		Chunk:    &sources.Chunk{},
	})

	if got := len(captured.findings); got != 1 {
		t.Fatalf("expected 1 emitted, got %d", got)
	}
	if string(captured.findings[0].Result.Raw) != "AKIAIOSFODNN7REAL" {
		t.Errorf("wrong finding kept: %q", captured.findings[0].Result.Raw)
	}
	if c := SuppressedCounter(wrapped); c != 1 {
		t.Errorf("expected 1 suppression, got %d", c)
	}
}

func TestSink_NilAllowlistIsPassThrough(t *testing.T) {
	captured := &captureSink{}
	wrapped := NewAllowlist(nil, captured)
	wrapped.Emit(Finding{Result: detectors.Result{Raw: []byte("x")}})
	if len(captured.findings) != 1 {
		t.Fatalf("nil allowlist must pass-through")
	}
	if c := SuppressedCounter(wrapped); c != -1 {
		t.Errorf("counter on pass-through must be -1, got %d", c)
	}
}

type captureSink struct {
	mu       sync.Mutex
	findings []Finding
}

func (c *captureSink) Emit(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, f)
}
func (c *captureSink) Close() error { return nil }
