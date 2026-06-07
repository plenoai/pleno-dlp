package piidb

import (
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type collectSink struct {
	mu       sync.Mutex
	findings []engine.Finding
	closed   bool
}

func (s *collectSink) Emit(f engine.Finding) {
	s.mu.Lock()
	s.findings = append(s.findings, f)
	s.mu.Unlock()
}

func (s *collectSink) Close() error {
	s.closed = true
	return nil
}

func TestSink_NonPII_PassThrough(t *testing.T) {
	inner := &collectSink{}
	sink := NewSink(inner)
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/app/config.yml"},
		},
	}
	f := engine.Finding{
		Result: detectors.Result{
			DetectorType: detectors.AWS,
			Severity:     detectors.SeverityHigh,
			Raw:          []byte("AKIAIOSFODNN7EXAMPLE"),
			ExtraData:    map[string]string{},
		},
		Chunk:    chunk,
		Detector: detectors.AWS,
	}
	sink.Emit(f)
	if len(inner.findings) != 1 {
		t.Fatalf("non-PII should pass through immediately, got %d findings", len(inner.findings))
	}
	if inner.findings[0].Result.Severity != detectors.SeverityHigh {
		t.Error("non-PII severity should be unchanged")
	}
}

func TestSink_PII_Buffered_Until_Flush(t *testing.T) {
	inner := &collectSink{}
	sink := NewSink(inner)
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/data/users.csv"},
		},
	}
	for i := 0; i < 3; i++ {
		sink.Emit(engine.Finding{
			Result: detectors.Result{
				DetectorType: detectors.PIIAnonymize,
				Severity:     detectors.SeverityMedium,
				Raw:          []byte("test@example.com"),
				ExtraData:    map[string]string{"finding_class": "pii"},
			},
			Chunk:    chunk,
			Detector: detectors.PIIAnonymize,
		})
	}
	if len(inner.findings) != 0 {
		t.Fatalf("PII should be buffered, but got %d findings in inner", len(inner.findings))
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(inner.findings) != 3 {
		t.Fatalf("after Flush, expected 3 PII findings forwarded, got %d", len(inner.findings))
	}
	for i, f := range inner.findings {
		if f.Result.Severity != detectors.SeverityHigh {
			t.Errorf("finding[%d]: expected escalated High severity, got %v", i, f.Result.Severity)
		}
		if f.Result.ExtraData["pii_db_candidate"] != "true" {
			t.Errorf("finding[%d]: missing pii_db_candidate", i)
		}
	}
}

func TestSink_Close_Flushes_And_Closes_Inner(t *testing.T) {
	inner := &collectSink{}
	sink := NewSink(inner)
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/data/dump.sql"},
		},
	}
	for i := 0; i < 5; i++ {
		sink.Emit(engine.Finding{
			Result: detectors.Result{
				DetectorType: detectors.PIIAnonymize,
				Severity:     detectors.SeverityMedium,
				Raw:          []byte("data"),
				ExtraData:    map[string]string{"finding_class": "pii"},
			},
			Chunk:    chunk,
			Detector: detectors.PIIAnonymize,
		})
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if len(inner.findings) != 5 {
		t.Fatalf("Close should flush, got %d findings", len(inner.findings))
	}
	if !inner.closed {
		t.Error("Close should propagate to inner")
	}
	for _, f := range inner.findings {
		if f.Result.Severity != detectors.SeverityCritical {
			t.Errorf("5 PII in .sql should be Critical, got %v", f.Result.Severity)
		}
	}
}

func TestSink_Flush_Idempotent(t *testing.T) {
	inner := &collectSink{}
	sink := NewSink(inner)
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/data/list.csv"},
		},
	}
	sink.Emit(engine.Finding{
		Result: detectors.Result{
			DetectorType: detectors.PIIAnonymize,
			Severity:     detectors.SeverityMedium,
			Raw:          []byte("x"),
			ExtraData:    map[string]string{"finding_class": "pii"},
		},
		Chunk:    chunk,
		Detector: detectors.PIIAnonymize,
	})
	_ = sink.Flush()
	_ = sink.Flush()
	if len(inner.findings) != 1 {
		t.Errorf("double Flush should not duplicate findings, got %d", len(inner.findings))
	}
}
