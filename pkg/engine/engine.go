// Package engine drives the scan loop: it pulls chunks from a Source, runs
// each registered Detector against chunks whose data contains at least one of
// the detector's keywords, and forwards results to the configured output sink.
//
// This file contains only the skeleton; concrete chunking, dedup, and filter
// behavior lives in dedup.go / filter.go and is filled in by core-engineer.
package engine

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/decoder"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type Finding struct {
	Result   detectors.Result
	Chunk    *sources.Chunk
	Detector detectors.DetectorType
}

type Sink interface {
	Emit(Finding)
	Close() error
}

type Options struct {
	Verify      bool
	Concurrency int
}

type Engine struct {
	opts  Options
	dets  []detectors.Detector
	sink  Sink
	stats statsCounters
}

// Stats summarises a completed scan. It is the user-facing snapshot derived
// from the engine's atomic counters; safe to serialise as JSON.
//
// Chunks counts every leaf chunk after archive expansion (one zip entry
// scanned = one chunk). Bytes counts the raw bytes fed to the keyword
// match — decoder variants don't double-count. Findings is the count
// before dedup; the CLI's countingSink owns the post-dedup tally.
type Stats struct {
	Chunks   int64         `json:"chunks"`
	Bytes    int64         `json:"bytes"`
	Findings int64         `json:"findings"`
	Duration time.Duration `json:"duration"`
}

// statsCounters holds the engine-side atomic counters. Lives alongside the
// Engine rather than as a separate field on Run so partial progress is
// observable from another goroutine if ever needed (eg a future progress
// reporter polling on a tick).
type statsCounters struct {
	chunks   atomic.Int64
	bytes    atomic.Int64
	findings atomic.Int64
}

// Stats returns a snapshot of the engine counters. Run() calls this at the
// end and stamps Duration; callers that want intermediate progress can poll
// this directly (Duration will be zero in that case).
func (e *Engine) Stats() Stats {
	return Stats{
		Chunks:   e.stats.chunks.Load(),
		Bytes:    e.stats.bytes.Load(),
		Findings: e.stats.findings.Load(),
	}
}

func New(opts Options, sink Sink) *Engine {
	return NewWithDetectors(detectors.All(), opts, sink)
}

// NewWithDetectors builds an engine with an explicit detector list. The CLI
// uses this to compose registered built-ins with custom rules loaded from
// disk; tests use it to inject pinpoint detectors. Concurrency is clamped
// here so callers don't need to remember the floor.
func NewWithDetectors(dets []detectors.Detector, opts Options, sink Sink) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	return &Engine{opts: opts, dets: dets, sink: sink}
}

// Run streams chunks from src and dispatches them across worker goroutines.
// Returns when src.Chunks returns or ctx is cancelled. Engine stats are
// available via Stats() during and after Run; the returned Stats has its
// Duration field stamped from the wall-clock time of the call.
func (e *Engine) Run(ctx context.Context, src sources.Source) error {
	_, err := e.RunWithStats(ctx, src)
	return err
}

// RunWithStats is Run plus a Stats snapshot. The CLI uses this to render
// "Scanned N chunks in T" on stderr without re-fetching from the engine.
func (e *Engine) RunWithStats(ctx context.Context, src sources.Source) (Stats, error) {
	start := time.Now()
	ch := make(chan *sources.Chunk, e.opts.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < e.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range ch {
				e.scanChunk(ctx, c)
			}
		}()
	}

	srcErr := src.Chunks(ctx, ch)
	close(ch)
	wg.Wait()
	s := e.Stats()
	s.Duration = time.Since(start)
	return s, srcErr
}

func (e *Engine) scanChunk(ctx context.Context, c *sources.Chunk) {
	// Archive expansion runs first: if the chunk is a zip / tar / gzip,
	// every inner entry becomes a synthetic chunk and is scanned in
	// place. Plain (non-archive) chunks fall through to the decoder
	// pipeline below unchanged. archive.Walk returns nil quickly for
	// non-archive bytes, so the cold path is one byte-prefix compare.
	if archive.LooksLikeArchive(c.Data) {
		entries, _ := archive.Walk(archiveRootName(c), c.Data, archive.Limits{})
		for _, entry := range entries {
			inner := *c // shallow copy preserves source metadata
			inner.Data = entry.Data
			// Embed the inner archive path into the finding's
			// ExtraData via the dedup keying — the chunk metadata
			// stays as the on-disk file, the entry path travels
			// alongside via Result.ExtraData["archive_path"]
			// stamped after detection.
			e.scanChunkLeaf(ctx, &inner, entry.Path)
		}
		return
	}
	e.scanChunkLeaf(ctx, c, "")
}

// archiveRootName picks a meaningful identifier for the outer archive
// when composing inner entry paths. Falls back to the chunk's source
// type when no filesystem-shaped name is available.
func archiveRootName(c *sources.Chunk) string {
	if c == nil {
		return ""
	}
	md := c.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path
	case md.Git != nil:
		return md.Git.File
	case md.GitHub != nil:
		return md.GitHub.File
	}
	return c.SourceName
}

// scanChunkLeaf runs every detector against a single chunk after archive
// expansion. archivePath is non-empty for inner entries; empty for plain
// chunks. The path is stamped into Result.ExtraData so output can render
// "leak.txt!secret.env" trails.
func (e *Engine) scanChunkLeaf(ctx context.Context, c *sources.Chunk, archivePath string) {
	e.stats.chunks.Add(1)
	e.stats.bytes.Add(int64(len(c.Data)))
	// Variants[0] is always c.Data unchanged (Source=""). Subsequent
	// entries are base64/percent/hex decode results, included only when
	// the chunk contained candidate runs. The cost is one regex sweep
	// per chunk on the cold path — paid once whether or not any detector
	// runs — and amortises against the keyword-matching that follows.
	variants := decoder.Variants(c.Data)

	for _, d := range e.dets {
		kws := d.Keywords()
		for _, v := range variants {
			if !keywordMatch(v.Data, kws) {
				continue
			}
			results, err := d.FromData(ctx, e.opts.Verify, v.Data)
			if err != nil {
				continue
			}
			for _, r := range results {
				if v.Source != "" {
					// Mark which decode produced the hit so output
					// can disambiguate "found in base64-encoded
					// payload" from "found in plain text".
					if r.ExtraData == nil {
						r.ExtraData = map[string]string{}
					}
					r.ExtraData["decoded_from"] = v.Source
				}
				// Detectors may set Severity directly; when zero
				// (the default), derive one so every finding is
				// triageable downstream.
				if r.Severity == detectors.SeverityUnknown {
					r.Severity = detectors.DefaultSeverity(d.Type(), r.Verified)
				}
				if archivePath != "" {
					if r.ExtraData == nil {
						r.ExtraData = map[string]string{}
					}
					r.ExtraData["archive_path"] = archivePath
				}
				e.stats.findings.Add(1)
				e.sink.Emit(Finding{Result: r, Chunk: c, Detector: d.Type()})
			}
		}
	}
}

// keywordMatch returns true when data contains any keyword (case-insensitive).
// Empty keyword list always returns false — a detector with no keywords is a
// configuration mistake, not an opt-in to scan everything.
func keywordMatch(data []byte, kws []string) bool {
	if len(kws) == 0 {
		return false
	}
	lower := bytes.ToLower(data)
	for _, kw := range kws {
		if bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			return true
		}
	}
	return false
}
