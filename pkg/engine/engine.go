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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/decoder"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Finding is the engine's per-emit payload. VerifierBacked is stamped by
// scanChunkLeaf via a runtime interface assertion against the emitting
// detector and is the input to dedup's cross-detector collision rule
// (Verifier > non-Verifier when two detectors fire on identical raw
// bytes at the same location). Keeping it on the Finding rather than
// re-running the assertion in dedup means the dedup sink stays free of
// detector-package coupling.
type Finding struct {
	Result         detectors.Result
	Chunk          *sources.Chunk
	Detector       detectors.DetectorType
	VerifierBacked bool
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
//
// Detector ordering matters for the dedup cross-detector collision rule:
// when a provider-specific Verifier-backed detector and the generic
// high-entropy detector both fire on the same raw bytes at the same
// location, dedup keeps the first emitted finding for that key.
// Putting Verifier-backed detectors first means the provider hit lands
// before generic — the user sees the higher-confidence finding and the
// generic noise is suppressed downstream. The sort is stable so the
// relative order of Verifier-backed detectors (and the relative order
// of non-Verifier detectors) is preserved.
func NewWithDetectors(dets []detectors.Detector, opts Options, sink Sink) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	ordered := append([]detectors.Detector(nil), dets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		_, vi := ordered[i].(detectors.Verifier)
		_, vj := ordered[j].(detectors.Verifier)
		// true (Verifier-backed) sorts before false.
		return vi && !vj
	})
	return &Engine{opts: opts, dets: ordered, sink: sink}
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
		_, isVerifier := d.(detectors.Verifier)
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
				// Cross-cutting blast-radius rollup: any per-provider
				// signal (*_high_risk, *_high_value, *_privileged) gets
				// promoted to a stable `blast_radius=true` so downstream
				// triage can filter without knowing the per-provider
				// vocabulary. Driftwood-pattern detectors set those
				// flags themselves; the engine just unifies them.
				tagBlastRadius(&r)
				e.stats.findings.Add(1)
				e.sink.Emit(Finding{
					Result:         r,
					Chunk:          c,
					Detector:       d.Type(),
					VerifierBacked: isVerifier,
				})
			}
		}
	}
}

// blastRadiusSuffixes are the per-provider ExtraData keys that signal an
// elevated triage priority. A finding gets `blast_radius=true` when any
// key in its ExtraData ends with one of these AND the value is "true".
//
// We match by suffix instead of an exact key list so adding a new
// driftwood-style provider doesn't require an engine edit. Per-provider
// fields like `aws_privileged`, `slack_privileged`, `stripe_high_value`,
// `npm_high_risk` all roll up automatically.
var blastRadiusSuffixes = []string{
	"_privileged",
	"_high_value",
	"_high_risk",
}

func tagBlastRadius(r *detectors.Result) {
	if r.ExtraData == nil {
		return
	}
	for k, v := range r.ExtraData {
		if v != "true" {
			continue
		}
		for _, suf := range blastRadiusSuffixes {
			if strings.HasSuffix(k, suf) {
				r.ExtraData["blast_radius"] = "true"
				return
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
