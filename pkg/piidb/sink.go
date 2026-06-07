package piidb

import (
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// Sink wraps a downstream engine.Sink and applies PIIDB candidate
// classification to PII findings before forwarding. Non-PII findings
// are forwarded immediately (no buffering latency). PII findings are
// buffered until Close, then classified as a batch and forwarded with
// escalated severity and explainability metadata.
//
// This design means PII findings appear in output AFTER all non-PII
// findings within the same scan. This ordering trade-off is acceptable
// because output formats (JSON array, SARIF) are unordered collections,
// and the table formatter renders in arrival order which merely groups
// PII at the end — a reasonable UX.
type Sink struct {
	inner engine.Sink
	mu    sync.Mutex
	pii   []engine.Finding
}

// NewSink creates a PIIDB classification sink wrapping inner. Non-PII
// findings pass through immediately; PII findings are buffered for
// batch classification at Close time.
func NewSink(inner engine.Sink) *Sink {
	return &Sink{inner: inner, pii: make([]engine.Finding, 0, 64)}
}

func (s *Sink) Emit(f engine.Finding) {
	if !isPII(f) {
		s.inner.Emit(f)
		return
	}
	s.mu.Lock()
	s.pii = append(s.pii, f)
	s.mu.Unlock()
}

// Flush classifies buffered PII findings and forwards them to the
// inner sink. Safe to call multiple times; subsequent calls are no-ops.
// Must be called before reading counter state (e.g. for summary output)
// because PII findings only reach the counter after flush.
func (s *Sink) Flush() error {
	s.mu.Lock()
	pii := s.pii
	s.pii = nil
	s.mu.Unlock()

	if len(pii) > 0 {
		classifications := Classify(pii)
		for i := range pii {
			ApplyClassification(&pii[i], classifications[i])
			s.inner.Emit(pii[i])
		}
	}
	return nil
}

func (s *Sink) Close() error {
	if err := s.Flush(); err != nil {
		return err
	}
	return s.inner.Close()
}
