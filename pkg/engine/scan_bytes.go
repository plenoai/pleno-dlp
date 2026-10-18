package engine

import (
	"context"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Result is a finding returned by ScanBytes. It aliases detectors.Result so
// callers that already handle the detector contract (for example to redact
// Result.Raw) need no conversion, while still reading as an engine-owned
// result in the ScanBytes signature.
type Result = detectors.Result

// bytesSource adapts one already-buffered body to the Source contract. Using
// the normal engine pipeline means ScanBytes inherits archive expansion,
// decoder variants, keyword prefilter, vicinity dispatch, and result
// finalisation instead of re-deriving them.
type bytesSource struct {
	chunk *sources.Chunk
}

func (s *bytesSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}

func (s *bytesSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	select {
	case ch <- s.chunk:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (s *bytesSource) Type() sources.SourceType { return sources.SourceUnknown }

// resultCollector is the Sink ScanBytes installs to capture emitted findings.
// Workers may emit concurrently, so the append is mutex-protected.
type resultCollector struct {
	mu      sync.Mutex
	results []Result
}

func (c *resultCollector) Emit(f Finding) {
	c.mu.Lock()
	c.results = append(c.results, f.Result)
	c.mu.Unlock()
}

func (c *resultCollector) Close() error { return nil }

func (c *resultCollector) snapshot() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Result, len(c.results))
	copy(out, c.results)
	return out
}

// ScanBytes scans an in-memory buffer with the full detector registry and
// returns every finding. It is the offline entry point used by latency-
// sensitive callers (crash telemetry redaction, pre-commit / agent hooks)
// that previously re-implemented the keyword prefilter and FromData
// iteration over the detector registry.
//
// ScanBytes is always offline: NoVerify is forced so a caller can never
// trigger detector verification network calls, regardless of what opts
// carries. Other Options fields (for example Concurrency) are honoured.
//
// The returned results follow engine emission order. Findings still honour
// decoded_from / archive_path metadata and severity defaulting; dedup and
// allowlisting remain sink-layer concerns the caller can apply afterward.
func ScanBytes(ctx context.Context, data []byte, opts Options) ([]Result, error) {
	return ScanBytesWithDetectors(ctx, detectors.All(), data, opts)
}

// ScanBytesWithDetectors is ScanBytes against an explicit detector set. It
// exists so internal callers and tests can scan a buffer without the global
// detector registry; ScanBytes delegates here with detectors.All().
func ScanBytesWithDetectors(ctx context.Context, dets []detectors.Detector, data []byte, opts Options) ([]Result, error) {
	opts.NoVerify = true
	collector := &resultCollector{}
	eng := NewWithDetectors(dets, opts, collector)
	src := &bytesSource{chunk: &sources.Chunk{
		SourceType: sources.SourceUnknown,
		SourceName: "scan-bytes",
		Data:       data,
	}}
	_, err := eng.RunWithStats(ctx, src)
	return collector.snapshot(), err
}
