package engine

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type fakeDetector struct{ needle string }

func (f fakeDetector) Keywords() []string         { return []string{"AKIA"} }
func (fakeDetector) Type() detectors.DetectorType { return detectors.AWS }
func (f fakeDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !contains(data, []byte(f.needle)) {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte(f.needle),
	}}, nil
}

func contains(haystack, needle []byte) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type fakeSource struct{ data []byte }

func (fakeSource) Init(context.Context, string, int64, int64, bool, []byte, int) error { return nil }
func (fakeSource) Type() sources.SourceType                                            { return sources.SourceFilesystem }
func (s fakeSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	c := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Data:       s.data,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/tmp/fake", Line: 1},
		},
	}
	select {
	case ch <- c:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func TestDecoderIntegration_FindsBase64HiddenSecret(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	hidden := base64.StdEncoding.EncodeToString([]byte("Authorization: " + akia))
	raw := []byte("export AUTH=" + hidden)

	sink := &recordingSink{}
	eng := NewWithDetectors(
		[]detectors.Detector{fakeDetector{needle: akia}},
		Options{Concurrency: 1},
		sink,
	)

	if err := eng.Run(context.Background(), fakeSource{data: raw}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.findings) != 1 {
		t.Fatalf("expected 1 finding from base64-hidden secret; got %d", len(sink.findings))
	}
	f := sink.findings[0]
	if got := string(f.Result.Raw); got != akia {
		t.Fatalf("finding.Raw = %q, want %q", got, akia)
	}
	if got := f.Result.ExtraData["decoded_from"]; got != "base64" {
		t.Fatalf("ExtraData[decoded_from] = %q, want %q", got, "base64")
	}
}

func TestDecoderIntegration_PlainTextPathUntagged(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	raw := []byte("aws_access_key_id=" + akia)

	sink := &recordingSink{}
	eng := NewWithDetectors(
		[]detectors.Detector{fakeDetector{needle: akia}},
		Options{Concurrency: 1},
		sink,
	)

	if err := eng.Run(context.Background(), fakeSource{data: raw}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(sink.findings))
	}
	if got, ok := sink.findings[0].Result.ExtraData["decoded_from"]; ok {
		t.Fatalf("plain-text hit should not carry decoded_from; got %q", got)
	}
}

var _ = sync.Mutex{}
