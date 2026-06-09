package stdin

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestChunks_EmitsSingleChunk(t *testing.T) {
	s := &Source{}
	if err := s.Init(t.Context(), "stdin", 0, 0, false, []byte(`{"label":"unit"}`), 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.SetReader(strings.NewReader("AKIAIOSFODNN7EXAMPLE"))

	ch := make(chan *sources.Chunk, 2)
	if err := s.Chunks(t.Context(), ch); err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	close(ch)

	got := drain(t, ch, time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	if string(got[0].Data) != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("data mismatch: %q", got[0].Data)
	}
	if got[0].SourceMetadata.Stdin == nil {
		t.Fatal("StdinMeta not set")
	}
	if got[0].SourceMetadata.Stdin.Label != "unit" {
		t.Fatalf("label override lost: %q", got[0].SourceMetadata.Stdin.Label)
	}
	if got[0].SourceType != sources.SourceStdin {
		t.Fatalf("source type mismatch: %v", got[0].SourceType)
	}
}

func TestChunks_DefaultLabel(t *testing.T) {
	s := &Source{}
	if err := s.Init(t.Context(), "stdin", 0, 0, false, nil, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.SetReader(strings.NewReader("hi"))

	ch := make(chan *sources.Chunk, 1)
	if err := s.Chunks(t.Context(), ch); err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	close(ch)
	got := drain(t, ch, time.Second)
	if len(got) != 1 || got[0].SourceMetadata.Stdin == nil {
		t.Fatalf("no chunk emitted")
	}
	if got[0].SourceMetadata.Stdin.Label != "<stdin>" {
		t.Fatalf("expected default label, got %q", got[0].SourceMetadata.Stdin.Label)
	}
}

func TestChunks_TruncationReportsError(t *testing.T) {
	s := &Source{}
	cfg := []byte(`{"max_bytes": 4}`)
	if err := s.Init(t.Context(), "stdin", 0, 0, false, cfg, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.SetReader(strings.NewReader("0123456789")) // 10 > 4

	ch := make(chan *sources.Chunk, 1)
	err := s.Chunks(t.Context(), ch)
	close(ch)

	if !IsTruncationError(err) {
		t.Fatalf("expected truncation sentinel, got %v", err)
	}
	got := drain(t, ch, time.Second)
	if len(got) != 1 {
		t.Fatalf("expected one (truncated) chunk before error, got %d", len(got))
	}
	if string(got[0].Data) != "0123" {
		t.Fatalf("expected first 4 bytes, got %q", got[0].Data)
	}
}

func TestResourceFingerprintCachesInputForChunks(t *testing.T) {
	s := &Source{}
	if err := s.Init(t.Context(), "stdin", 0, 0, false, []byte(`{"label":"unit"}`), 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.SetReader(strings.NewReader("secret=value"))

	fp, err := s.ResourceFingerprint(t.Context())
	if err != nil {
		t.Fatalf("ResourceFingerprint: %v", err)
	}
	if fp == "" {
		t.Fatal("ResourceFingerprint returned empty fingerprint")
	}

	ch := make(chan *sources.Chunk, 1)
	if err := s.Chunks(t.Context(), ch); err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	close(ch)
	got := drain(t, ch, time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	if string(got[0].Data) != "secret=value" {
		t.Fatalf("data mismatch after fingerprint: %q", got[0].Data)
	}
}

func TestIncrementalStateSkipsUnchangedInput(t *testing.T) {
	first := &Source{}
	if err := first.Init(t.Context(), "stdin", 0, 0, false, []byte(`{"label":"unit"}`), 1); err != nil {
		t.Fatalf("Init first: %v", err)
	}
	first.SetReader(strings.NewReader("same-input"))
	if _, err := first.ResourceFingerprint(t.Context()); err != nil {
		t.Fatalf("first ResourceFingerprint: %v", err)
	}
	ch := make(chan *sources.Chunk, 1)
	if err := first.Chunks(t.Context(), ch); err != nil {
		t.Fatalf("first Chunks: %v", err)
	}
	close(ch)
	if got := drain(t, ch, time.Second); len(got) != 1 {
		t.Fatalf("first chunks = %d, want 1", len(got))
	}

	second := &Source{}
	if err := second.Init(t.Context(), "stdin", 0, 0, false, []byte(`{"label":"unit"}`), 1); err != nil {
		t.Fatalf("Init second: %v", err)
	}
	if err := second.SetIncrementalState(first.IncrementalState()); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	second.SetReader(strings.NewReader("same-input"))
	if _, err := second.ResourceFingerprint(t.Context()); err != nil {
		t.Fatalf("second ResourceFingerprint: %v", err)
	}
	ch = make(chan *sources.Chunk, 1)
	if err := second.Chunks(t.Context(), ch); err != nil {
		t.Fatalf("second Chunks: %v", err)
	}
	close(ch)
	if got := drain(t, ch, time.Second); len(got) != 0 {
		t.Fatalf("second chunks = %d, want 0", len(got))
	}
}

func TestInit_RejectsBadJSON(t *testing.T) {
	s := &Source{}
	if err := s.Init(t.Context(), "stdin", 0, 0, false, []byte("{bad"), 1); err == nil {
		t.Fatal("expected init error on bad json")
	}
}

func TestChunks_RespectsContextCancel(t *testing.T) {
	s := &Source{}
	if err := s.Init(t.Context(), "stdin", 0, 0, false, nil, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.SetReader(bytes.NewReader([]byte("payload")))

	// Unbuffered channel + cancelled ctx must surface ctx.Err on send.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ch := make(chan *sources.Chunk)
	err := s.Chunks(ctx, ch)
	if err == nil {
		t.Fatal("expected ctx error")
	}
}

func drain(t *testing.T, ch <-chan *sources.Chunk, timeout time.Duration) []*sources.Chunk {
	t.Helper()
	var out []*sources.Chunk
	deadline := time.After(timeout)
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, c)
		case <-deadline:
			t.Fatalf("drain: timed out after %s with %d chunks", timeout, len(out))
		}
	}
}
