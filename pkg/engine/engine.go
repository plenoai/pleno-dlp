// Package engine drives the scan loop: it pulls chunks from a Source, runs
// each registered Detector against chunks whose data contains at least one of
// the detector's keywords, and forwards results to the configured output sink.
//
// This file contains only the skeleton; concrete chunking, dedup, and filter
// behavior lives in dedup.go / filter.go and is filled in by core-engineer.
package engine

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/ahocorasick"
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
	opts Options
	dets []detectors.Detector
	// isVerifier[i] is true when dets[i] satisfies detectors.Verifier.
	// Cached at construction time so the hot path doesn't re-run the
	// interface assertion per chunk.
	isVerifier []bool
	// wantsFull[i] is true when dets[i] opted in via FullChunkDetector.
	// Dispatch then passes the entire variant data (not a vicinity
	// slice) so BEGIN/END-style anchored regexes don't get split.
	wantsFull []bool
	// prefilter is the Aho-Corasick keyword matcher across the union of
	// every detector's lower-cased keywords. detectorIdxByPattern[p]
	// lists the detector indices unlocked when pattern p matches. Both
	// are nil when the engine has no detectors (test seam).
	prefilter            *ahocorasick.Matcher
	detectorIdxByPattern [][]int
	// lowerBufPool holds reusable lower-case scratch buffers (one per
	// scan invocation; sized to the chunk being scanned). Avoids the
	// per-detector bytes.ToLower copy that dominated the cold path.
	lowerBufPool sync.Pool
	// seenBufPool holds reusable bool[] of length len(dets), used by
	// scanChunkLeaf to collect "which detectors got a keyword hit"
	// without allocating per chunk.
	seenBufPool sync.Pool
	sink        Sink
	stats       statsCounters
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
	isVerifier := make([]bool, len(ordered))
	wantsFull := make([]bool, len(ordered))
	for i, d := range ordered {
		_, isVerifier[i] = d.(detectors.Verifier)
		if fc, ok := d.(detectors.FullChunkDetector); ok {
			wantsFull[i] = fc.WantsFullChunk()
		}
	}
	e := &Engine{
		opts:       opts,
		dets:       ordered,
		isVerifier: isVerifier,
		wantsFull:  wantsFull,
		sink:       sink,
	}
	e.buildPrefilter()
	return e
}

// buildPrefilter constructs the Aho-Corasick automaton over the union of
// lower-cased detector keywords. Multiple detectors may share a keyword
// ("key", "token", "api"); each keyword becomes one pattern, and the
// pattern's detectorIdxByPattern entry lists every detector that asked for
// it. The single pass at scan time then unions those lists.
//
// Keywords are stored lower-cased; the scan path lower-cases the input
// once into a pooled buffer to match. Empty keyword lists make the
// detector unreachable through the prefilter — same semantics as the old
// keywordMatch, which returned false for an empty list.
func (e *Engine) buildPrefilter() {
	if len(e.dets) == 0 {
		return
	}
	patternIDByKeyword := make(map[string]int)
	var patterns [][]byte
	var detectorIdxByPattern [][]int
	for di, d := range e.dets {
		for _, kw := range d.Keywords() {
			if kw == "" {
				continue
			}
			lk := strings.ToLower(kw)
			id, ok := patternIDByKeyword[lk]
			if !ok {
				id = len(patterns)
				patternIDByKeyword[lk] = id
				patterns = append(patterns, []byte(lk))
				detectorIdxByPattern = append(detectorIdxByPattern, nil)
			}
			detectorIdxByPattern[id] = append(detectorIdxByPattern[id], di)
		}
	}
	if len(patterns) == 0 {
		return
	}
	e.prefilter = ahocorasick.New(patterns)
	e.detectorIdxByPattern = detectorIdxByPattern
	e.seenBufPool.New = func() any {
		b := make([]bool, len(e.dets))
		return &b
	}
	e.lowerBufPool.New = func() any {
		b := make([]byte, 0, 4096)
		return &b
	}
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

// maxWindowSize and windowOverlap bound how much data any single
// dispatch sees. Detector regexes run in O(window_size); collapsing a
// 100 KiB file into one dispatch made every dispatched detector pay
// O(100 KiB) of regex stepping. Sliding a 32 KiB window keeps that cost
// flat regardless of file size. The overlap guarantees no secret of
// length <= overlap can fall on a window boundary and go unseen.
const (
	maxWindowSize  = 32 * 1024
	windowOverlap  = 1024
	windowStepSize = maxWindowSize - windowOverlap
)

// scanChunkLeaf runs every detector against a single chunk after archive
// expansion. archivePath is non-empty for inner entries; empty for plain
// chunks. The path is stamped into Result.ExtraData so output can render
// "leak.txt!secret.env" trails.
//
// Chunks larger than maxWindowSize are walked in overlapping windows so
// each detector regex sweep stays bounded — see the comment on the
// constants above for the rationale.
func (e *Engine) scanChunkLeaf(ctx context.Context, c *sources.Chunk, archivePath string) {
	e.stats.chunks.Add(1)
	e.stats.bytes.Add(int64(len(c.Data)))

	// No prefilter (e.g. detector list is empty in a test seam): nothing
	// to scan. Production callers always go through buildPrefilter.
	if e.prefilter == nil {
		return
	}

	// Pull a reusable lowercase buffer and a reusable per-detector "saw a
	// keyword hit?" bitmap from the pool. Both grow with chunk / detector
	// count; sync.Pool keeps the steady-state allocations near zero.
	lowerPtr := e.lowerBufPool.Get().(*[]byte)
	defer e.lowerBufPool.Put(lowerPtr)
	seenPtr := e.seenBufPool.Get().(*[]bool)
	defer e.seenBufPool.Put(seenPtr)

	// FullChunkDetector opt-ins (e.g. PrivateKeyPEM) see the entire
	// chunk independent of the windowing loop below. BEGIN/END
	// anchored regexes don't survive being split across a 32 KiB
	// window boundary even with overlap, so we pay the per-chunk
	// regex cost once on the whole chunk for that small set.
	e.runFullChunkDetectors(ctx, c, archivePath)

	data := c.Data
	if len(data) <= maxWindowSize {
		e.scanWindow(ctx, c, data, archivePath, lowerPtr, seenPtr)
		return
	}
	for start := 0; start < len(data); start += windowStepSize {
		end := start + maxWindowSize
		if end > len(data) {
			end = len(data)
		}
		e.scanWindow(ctx, c, data[start:end], archivePath, lowerPtr, seenPtr)
		if end == len(data) {
			break
		}
	}
}

// runFullChunkDetectors dispatches every detector that opted in via
// FullChunkDetector against the whole chunk in one pass — bypassing
// both the windowing loop and the vicinity-slice dispatch. The
// scanWindow path then SKIPs these detectors (see dispatch), so each
// FullChunk detector emits exactly once per chunk regardless of how
// many windows the chunk is split into.
func (e *Engine) runFullChunkDetectors(ctx context.Context, c *sources.Chunk, archivePath string) {
	// Decode variants from the whole chunk so an encoded PEM inside a
	// base64 blob still reaches the detector. Cheap when the chunk
	// has no candidate runs (byte-scan gates short-circuit).
	variants := decoder.Variants(c.Data)
	for _, v := range variants {
		for di := range e.dets {
			if !e.wantsFull[di] {
				continue
			}
			e.runDetectorOn(ctx, c, v, archivePath, di, v.Data)
		}
	}
}

// scanWindow runs the variant fan-out + dispatch for a single window of
// chunk bytes. Split out of scanChunkLeaf so the windowing loop stays a
// flat read.
func (e *Engine) scanWindow(ctx context.Context, c *sources.Chunk, window []byte, archivePath string, lowerPtr *[]byte, seenPtr *[]bool) {
	// Variants[0] is always window unchanged (Source=""). Subsequent
	// entries are base64/percent/hex decode results, included only when
	// the window contained candidate runs.
	variants := decoder.Variants(window)
	for _, v := range variants {
		matched := e.dispatch(ctx, c, v, archivePath, lowerPtr, seenPtr)
		if matched == 0 && v.Source == "" {
			// Most windows have zero hits; the empty path is the
			// common one. Nothing to do here — kept as a single
			// branch so the hot path stays compact.
			_ = matched
		}
	}
}

// vicinityRadius is how many bytes around each keyword hit a detector
// gets to see. Sized to cover the widest credential-shape regex
// captures in the codebase (private keys, JWTs) plus the
// keyword<->secret gap a generic credential line can introduce
// ("API_KEY = \"…long-multiline-comment…\"…token"). Beyond this radius
// the regex would have failed anyway, so trimming the window is sound
// for every detector whose match span fits inside.
const vicinityRadius = 2048

// dispatch lower-cases v.Data once into the pooled buffer, collects per-
// keyword AC hits, then runs each dispatched detector against the
// minimal vicinity slice that covers every one of its keyword hits.
//
// Without vicinity slicing a detector's regex would scan the full
// window even when the keyword fires in one corner — that turned every
// dispatched detector into an O(window_size) regex sweep. Sliced
// dispatch caps per-detector work at O(hits * 2*vicinityRadius), which
// is the dominant win on real-OSS workloads where most detectors fire
// on a single keyword instance.
//
// Returns the number of dispatched detectors so callers can keep
// accounting if they ever need it; current callers ignore it.
func (e *Engine) dispatch(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, lowerPtr *[]byte, seenPtr *[]bool) int {
	lower := lowerCaseInto((*lowerPtr)[:0], v.Data)
	*lowerPtr = lower
	seen := *seenPtr
	if cap(seen) < len(e.dets) {
		seen = make([]bool, len(e.dets))
		*seenPtr = seen
	} else {
		seen = seen[:len(e.dets)]
		for i := range seen {
			seen[i] = false
		}
	}
	hits := e.prefilter.MatchHitsInto(lower, nil)
	if len(hits) == 0 {
		return 0
	}
	// Group hits by detector: each detector sees the union of its
	// keyword-hit vicinities. We accumulate (start, end) byte ranges
	// per detector, merge overlapping ranges, then run FromData once
	// per merged range. The per-detector ranges array is small (most
	// detectors fire once per window); allocating it inline keeps the
	// code simple without showing up in the profile.
	dets := make(map[int][]vicinitySpan)
	for _, h := range hits {
		for _, di := range e.detectorIdxByPattern[h.PatternID] {
			// FullChunkDetector opt-ins are handled once per chunk
			// by runFullChunkDetectors. Skip them here so they don't
			// also fire per window — the regex would emit duplicate
			// findings into dedup.
			if e.wantsFull[di] {
				continue
			}
			start := h.End - vicinityRadius
			if start < 0 {
				start = 0
			}
			end := h.End + 1 + vicinityRadius
			if end > len(v.Data) {
				end = len(v.Data)
			}
			dets[di] = append(dets[di], vicinitySpan{start, end})
		}
	}
	dispatched := 0
	for di, spans := range dets {
		seen[di] = true
		dispatched++
		merged := mergeSpans(spans)
		for _, sp := range merged {
			e.runDetectorOn(ctx, c, v, archivePath, di, v.Data[sp.start:sp.end])
		}
	}
	return dispatched
}

type vicinitySpan struct{ start, end int }

// mergeSpans collapses overlapping/adjacent (sorted-on-the-fly) spans
// so each detector regex runs once per disjoint vicinity region. Sort
// by start, sweep, extend the active region until a gap appears.
func mergeSpans(spans []vicinitySpan) []vicinitySpan {
	if len(spans) <= 1 {
		return spans
	}
	// Insertion sort: per-detector hit counts are typically small (1-5),
	// where sort.Slice's setup cost dominates.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j-1].start > spans[j].start; j-- {
			spans[j-1], spans[j] = spans[j], spans[j-1]
		}
	}
	out := spans[:1]
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// runDetectorOn executes a single detector's FromData against a slice
// of variant bytes and forwards every result through the engine's
// finalisation pipeline (severity defaulting, decoded_from /
// archive_path stamping, blast-radius rollup, stats accounting, sink
// emission). The slice is a vicinity window the dispatcher computed
// from AC hits; detectors that needed the full variant before still
// see a slice that covers every keyword hit + vicinityRadius bytes on
// each side, which is the radius the credential regexes are written
// against. Pulled out of scanChunkLeaf so the inner dispatch loop
// stays a flat read.
func (e *Engine) runDetectorOn(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, data []byte) {
	d := e.dets[di]
	results, err := d.FromData(ctx, e.opts.Verify, data)
	if err != nil {
		return
	}
	for _, r := range results {
		if v.Source != "" {
			if r.ExtraData == nil {
				r.ExtraData = map[string]string{}
			}
			r.ExtraData["decoded_from"] = v.Source
		}
		if r.Severity == detectors.SeverityUnknown {
			r.Severity = detectors.DefaultSeverity(d.Type(), r.Verified)
		}
		if archivePath != "" {
			if r.ExtraData == nil {
				r.ExtraData = map[string]string{}
			}
			r.ExtraData["archive_path"] = archivePath
		}
		tagBlastRadius(&r)
		e.stats.findings.Add(1)
		e.sink.Emit(Finding{
			Result:         r,
			Chunk:          c,
			Detector:       d.Type(),
			VerifierBacked: e.isVerifier[di],
		})
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

// lowerCaseInto appends the ASCII-lower-case of src to dst and returns the
// resulting slice. ASCII-only because every detector keyword in pleno-dlp
// is ASCII; we leave non-ASCII bytes untouched rather than paying for
// unicode.ToLower on each byte. This is a hot path — one call per chunk
// variant — and matches the (also-ASCII) lowercasing done at engine
// construction over keyword sets.
func lowerCaseInto(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	} else {
		dst = dst[:len(src)]
	}
	for i, b := range src {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		dst[i] = b
	}
	return dst
}
