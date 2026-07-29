// Package engine drives chunk dispatch, detector execution, and sink emission.
package engine

import (
	"bytes"
	"context"
	"errors"
	"reflect"
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
	"golang.org/x/sync/singleflight"
)

type Finding struct {
	Result         detectors.Result
	Chunk          *sources.Chunk
	Detector       detectors.DetectorType
	VerifierBacked bool
	// SuppressedBy names the filter that suppressed this finding when it
	// is still being forwarded for audit purposes (e.g. --show-suppressed
	// routing a placeholder-filtered finding straight to the output
	// sink instead of only tallying it). Empty for every finding that
	// reaches a sink through the normal chain — a suppression sink sets
	// this immediately before its one audit Emit call, so it never
	// appears on a finding read back out of dedup or the engine's own
	// emission path.
	SuppressedBy string
}

type Sink interface {
	Emit(Finding)
	Close() error
}

type Options struct {
	Concurrency int
	// NoVerify skips the network round-trip in every Verifier detector's
	// FromData call (the `verify bool` parameter of the trufflehog
	// Detector contract is passed false instead of the unconditional
	// true). Findings are still emitted — this only removes the outbound
	// HTTP call, not the finding — with Verdict()==Unverified, since
	// Verify() is never attempted at all rather than attempted and
	// failing (that latter case is Verdict()==Indeterminate; see
	// detectors.Result.Verdict). Exists for latency-sensitive callers
	// (pre-commit / agent hooks, issue #303) that need an offline, fast
	// scan and are willing to trade verified confidence for it.
	NoVerify bool
}

type Engine struct {
	// runGate serializes RunWithStats calls while allowing a queued caller to
	// abandon acquisition when its context is canceled.
	runGate               chan struct{}
	opts                  Options
	dets                  []detectors.Detector
	isVerifier            []bool
	verificationCacheable []bool
	verificationUsesData  []bool
	wantsFull             []bool
	prefilter             *ahocorasick.Matcher
	detectorIdxByPattern  [][]int
	lowerBufPool          sync.Pool
	seenBufPool           sync.Pool
	sink                  Sink
	verificationCache     *verificationCache
	verificationFlights   singleflight.Group
	stats                 statsCounters
	failureMu             sync.Mutex
	failures              []ScanFailure
	failureTotal          int
	failureCounts         map[FailureKind]int
}

const builtInDetectorPackagePrefix = "github.com/plenoai/pleno-dlp/pkg/detectors/"

func isBuiltInDetectorImplementation(detector detectors.Detector) bool {
	detectorType := reflect.TypeOf(detector)
	if detectorType == nil {
		return false
	}
	for detectorType.Kind() == reflect.Pointer {
		detectorType = detectorType.Elem()
	}
	return strings.HasPrefix(detectorType.PkgPath(), builtInDetectorPackagePrefix)
}

// These built-in verifiers were audited to preserve candidate output and to
// return errors for transport failures, rate limits, provider 5xx responses,
// policy failures, and every other ambiguous outcome. The conservative
// allowlist prevents transient conditions from poisoning cached verdicts.
func builtInVerificationCacheSafe(detectorType detectors.DetectorType) bool {
	switch detectorType {
	case detectors.ArgoCD,
		detectors.BitbucketServer,
		detectors.DockerHub,
		detectors.Resend,
		detectors.SlackWebhook,
		detectors.Tailscale:
		return true
	default:
		return false
	}
}

type Stats struct {
	Chunks   int64         `json:"chunks"`
	Bytes    int64         `json:"bytes"`
	Findings int64         `json:"findings"`
	Duration time.Duration `json:"duration"`
	// VerificationCacheHits counts candidate verdicts served from cache.
	VerificationCacheHits int64 `json:"verification_cache_hits,omitempty"`
	// VerificationCacheMisses counts detector passes with at least one miss.
	VerificationCacheMisses int64 `json:"verification_cache_misses,omitempty"`
	// VerificationCacheHitsWasted counts partial candidate hits in missed passes.
	VerificationCacheHitsWasted  int64         `json:"verification_cache_hits_wasted,omitempty"`
	VerificationCacheBypasses    int64         `json:"verification_cache_bypasses,omitempty"`
	VerificationCacheEvictions   int64         `json:"verification_cache_evictions,omitempty"`
	VerifiedPassesSaved          int64         `json:"verified_passes_saved,omitempty"`
	VerifiedDetectorCalls        int64         `json:"verified_detector_calls,omitempty"`
	VerifiedDetectorCallDuration time.Duration `json:"verified_detector_call_duration,omitempty"`
}

type statsCounters struct {
	chunks                      atomic.Int64
	bytes                       atomic.Int64
	findings                    atomic.Int64
	verificationCacheHits       atomic.Int64
	verificationCacheMisses     atomic.Int64
	verificationCacheHitsWasted atomic.Int64
	verificationCacheBypasses   atomic.Int64
	verificationCacheEvictions  atomic.Int64
	verifiedPassesSaved         atomic.Int64
	verifiedDetectorCalls       atomic.Int64
	verifiedDetectorCallNanos   atomic.Int64
}

// AggregateStats returns lifetime counters across every completed or active
// run on this Engine. Use RunWithStats when per-run metrics are required.
func (e *Engine) AggregateStats() Stats {
	return Stats{
		Chunks:                       e.stats.chunks.Load(),
		Bytes:                        e.stats.bytes.Load(),
		Findings:                     e.stats.findings.Load(),
		VerificationCacheHits:        e.stats.verificationCacheHits.Load(),
		VerificationCacheMisses:      e.stats.verificationCacheMisses.Load(),
		VerificationCacheHitsWasted:  e.stats.verificationCacheHitsWasted.Load(),
		VerificationCacheBypasses:    e.stats.verificationCacheBypasses.Load(),
		VerificationCacheEvictions:   e.stats.verificationCacheEvictions.Load(),
		VerifiedPassesSaved:          e.stats.verifiedPassesSaved.Load(),
		VerifiedDetectorCalls:        e.stats.verifiedDetectorCalls.Load(),
		VerifiedDetectorCallDuration: time.Duration(e.stats.verifiedDetectorCallNanos.Load()),
	}
}

// Stats is retained for compatibility. Deprecated: use AggregateStats for
// lifetime counters or RunWithStats for metrics from one run.
func (e *Engine) Stats() Stats { return e.AggregateStats() }

func New(opts Options, sink Sink) *Engine {
	return NewWithDetectors(detectors.All(), opts, sink)
}

func NewWithDetectors(dets []detectors.Detector, opts Options, sink Sink) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	ordered := append([]detectors.Detector(nil), dets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		_, vi := ordered[i].(detectors.Verifier)
		_, vj := ordered[j].(detectors.Verifier)
		return vi && !vj
	})
	isVerifier := make([]bool, len(ordered))
	verificationCacheable := make([]bool, len(ordered))
	verificationUsesData := make([]bool, len(ordered))
	wantsFull := make([]bool, len(ordered))
	for i, d := range ordered {
		_, isVerifier[i] = d.(detectors.Verifier)
		builtIn := isBuiltInDetectorImplementation(d)
		if policy, ok := d.(detectors.VerificationCacheSafe); ok {
			verificationCacheable[i] = policy.VerificationCacheCanStoreVerdicts()
		} else {
			verificationCacheable[i] = builtIn &&
				builtInVerificationCacheSafe(d.Type())
		}
		if contextual, ok := d.(detectors.VerificationCacheInputDependent); ok {
			verificationUsesData[i] = contextual.VerificationCacheUsesFullInput()
		} else if !builtIn {
			verificationUsesData[i] = true
		}
		if fc, ok := d.(detectors.FullChunkDetector); ok {
			wantsFull[i] = fc.WantsFullChunk()
		}
	}
	e := &Engine{
		runGate:               make(chan struct{}, 1),
		opts:                  opts,
		dets:                  ordered,
		isVerifier:            isVerifier,
		verificationCacheable: verificationCacheable,
		verificationUsesData:  verificationUsesData,
		wantsFull:             wantsFull,
		sink:                  sink,
		verificationCache:     newVerificationCache(defaultVerificationCacheCapacity),
	}
	e.buildPrefilter()
	return e
}

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

func (e *Engine) Run(ctx context.Context, src sources.Source) error {
	_, err := e.RunWithStats(ctx, src)
	return err
}

func (e *Engine) RunWithStats(ctx context.Context, src sources.Source) (Stats, error) {
	select {
	case e.runGate <- struct{}{}:
		defer func() { <-e.runGate }()
	case <-ctx.Done():
		return Stats{}, ctx.Err()
	}
	e.verificationCache.clear()
	defer e.verificationCache.clear()

	start := time.Now()
	before := e.AggregateStats()
	e.resetFailures()
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
	degradedErr := e.takeFailures()
	after := e.AggregateStats()
	stats := Stats{
		Chunks:                       after.Chunks - before.Chunks,
		Bytes:                        after.Bytes - before.Bytes,
		Findings:                     after.Findings - before.Findings,
		Duration:                     time.Since(start),
		VerificationCacheHits:        after.VerificationCacheHits - before.VerificationCacheHits,
		VerificationCacheMisses:      after.VerificationCacheMisses - before.VerificationCacheMisses,
		VerificationCacheHitsWasted:  after.VerificationCacheHitsWasted - before.VerificationCacheHitsWasted,
		VerificationCacheBypasses:    after.VerificationCacheBypasses - before.VerificationCacheBypasses,
		VerificationCacheEvictions:   after.VerificationCacheEvictions - before.VerificationCacheEvictions,
		VerifiedPassesSaved:          after.VerifiedPassesSaved - before.VerifiedPassesSaved,
		VerifiedDetectorCalls:        after.VerifiedDetectorCalls - before.VerifiedDetectorCalls,
		VerifiedDetectorCallDuration: after.VerifiedDetectorCallDuration - before.VerifiedDetectorCallDuration,
	}
	return stats, errors.Join(srcErr, degradedErr)
}

func (e *Engine) resetFailures() {
	e.failureMu.Lock()
	e.failures = e.failures[:0]
	e.failureTotal = 0
	e.failureCounts = make(map[FailureKind]int)
	e.failureMu.Unlock()
}

func (e *Engine) recordFailure(failure ScanFailure) {
	e.failureMu.Lock()
	e.failureTotal++
	e.failureCounts[failure.Kind]++
	if len(e.failures) < maxFailureExamples {
		e.failures = append(e.failures, failure)
	}
	e.failureMu.Unlock()
}

func (e *Engine) takeFailures() error {
	e.failureMu.Lock()
	failures := append([]ScanFailure(nil), e.failures...)
	total := e.failureTotal
	counts := make(map[FailureKind]int, len(e.failureCounts))
	for kind, count := range e.failureCounts {
		counts[kind] = count
	}
	e.failures = e.failures[:0]
	e.failureTotal = 0
	e.failureCounts = nil
	e.failureMu.Unlock()
	if total == 0 {
		return nil
	}
	return &DegradedError{Total: total, Counts: counts, Failures: failures}
}

// scanChunk expands archive chunks and dispatches every leaf chunk.
func (e *Engine) scanChunk(ctx context.Context, c *sources.Chunk) {
	if archive.LooksLikeArchive(c.Data) {
		const archiveTimeout = 5 * time.Second
		archiveCtx, cancel := context.WithTimeout(ctx, archiveTimeout)
		entries, err := archive.WalkContext(archiveCtx, archiveRootName(c), c.Data, archive.Limits{
			MaxDepth: 3, MaxEntryBytes: 10 << 20, MaxExpandedBytes: 50 << 20, MaxFiles: 1000,
		})
		cancel()
		if err != nil {
			// Partial-failure: entries after the failure point were
			// never extracted and will not be scanned. Surface it so
			// the data-loss risk is visible instead of silent.
			e.recordFailure(ScanFailure{Kind: FailureArchive, Source: archiveRootName(c), Err: err})
		}
		for _, entry := range entries {
			inner := *c
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

	// FullChunkDetector opt-ins see the entire chunk independent of
	// the windowing loop below. BEGIN/END
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
		// A cancelled scan stops sliding the window; remaining windows
		// of this chunk go unscanned by design.
		if ctx.Err() != nil {
			return
		}
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
// scanWindow path then SKIPs these detectors, so each
// FullChunk detector emits exactly once per chunk regardless of how
// many windows the chunk is split into.
func (e *Engine) runFullChunkDetectors(ctx context.Context, c *sources.Chunk, archivePath string) {
	// Decode variants from the whole chunk so an encoded PEM inside a
	// base64 blob still reaches the detector. Cheap when the chunk
	// has no candidate runs.
	variants := decoder.Variants(c.Data)
	for _, v := range variants {
		// Stop dispatching full-chunk detectors once the scan is
		// cancelled — same forfeit-completeness contract as the
		// windowed dispatch path.
		if ctx.Err() != nil {
			return
		}
		for di := range e.dets {
			if !e.wantsFull[di] {
				continue
			}
			e.runDetectorOn(ctx, c, v, archivePath, di, v.Data)
		}
	}
}

// scanWindow runs the variant fan-out + dispatch for a single window of
// chunk bytes.
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
// gets to see. Sized to cover the widest single-hit regex span in the
// codebase: GCP service-account JSON (2-3 KB top to bottom, keyword
// `service_account` anchored near the top), paired-secret detectors
// like Bandwidth (each member within 256 B of the keyword, pair span
// ≤512 B), and credential lines with embedded multi-line comments.
// Detectors whose match span genuinely exceeds this — PEM BEGIN/END
// pairs reaching 6+ KB on RSA-8192 — opt out via
// `detectors.FullChunkDetector`. 4 KiB is the value that lets every
// non-PEM real-world detector run on a vicinity slice without missing
// findings against the pre-optimisation baseline on corpus-d.
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
	// keyword-hit vicinities. Accumulate start/end byte ranges per
	// detector, merge overlapping ranges, then run FromData once per
	// merged range.
	dets := make(map[int][]vicinitySpan)
	var detectorOrder []int
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
			if _, exists := dets[di]; !exists {
				// Detector indices follow e.dets, which NewWithDetectors sorts
				// verifier-first. Record each detector once, then restore that
				// order below instead of ranging over the randomized map.
				detectorOrder = append(detectorOrder, di)
			}
			dets[di] = append(dets[di], vicinitySpan{start, end})
		}
	}
	sort.Ints(detectorOrder)
	dispatched := 0
	for _, di := range detectorOrder {
		spans := dets[di]
		// Bail out of the per-detector dispatch on cancellation so a
		// cancelled scan stops running detectors mid-window.
		if ctx.Err() != nil {
			return dispatched
		}
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

// mergeSpans collapses overlapping/adjacent spans so each detector
// regex runs once per disjoint vicinity region. Sort
// by start, sweep, extend the active region until a gap appears.
func mergeSpans(spans []vicinitySpan) []vicinitySpan {
	if len(spans) <= 1 {
		return spans
	}
	// Insertion sort: per-detector hit counts are typically small,
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
// against.
func (e *Engine) runDetectorOn(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, data []byte) {
	d := e.dets[di]
	// Verification defaults to unconditional-true: the bool is the
	// trufflehog Detector contract, not normally a configurable option.
	// Options.NoVerify is the one deliberate escape hatch (issue #303) —
	// set it and every Verifier detector's FromData skips its network
	// round-trip, keeping the scan fully offline instead of only
	// filtering verified findings out afterward at the sink layer.
	results, err := e.fromData(ctx, d, di, data)
	if err != nil {
		// Cancellation of the scan context is the expected shutdown path,
		// not degraded coverage. A detector's own deadline error while the
		// scan context remains live is a real execution failure; provider
		// verification failures belong on Result.VerificationErr instead.
		if ctx.Err() == nil {
			e.recordFailure(ScanFailure{Kind: FailureDetector, Source: archiveRootName(c), Detector: d.Type(), Err: err})
		}
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
			r.Severity = detectors.DefaultSeverityForVerdict(d.Type(), r.Verdict())
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
			Chunk:          chunkWithMatchLine(c, r.Raw),
			Detector:       d.Type(),
			VerifierBacked: e.isVerifier[di],
		})
	}
}

// computeLineFromMatch returns the 1-based line of the first occurrence of
// raw within data, offset by base (the chunk's starting line). It returns 0
// when raw is absent so callers leave the existing line untouched rather
// than reporting a wrong one.
func computeLineFromMatch(data, raw []byte, base int) int {
	if len(raw) == 0 {
		return 0
	}
	idx := bytes.Index(data, raw)
	if idx < 0 {
		return 0
	}
	if base <= 0 {
		base = 1
	}
	return base + bytes.Count(data[:idx], []byte{'\n'})
}

// chunkWithMatchLine returns a shallow copy of c whose source-metadata line
// points at where the matched secret actually sits, instead of the chunk's
// start line. A filesystem/sqldump chunk is a whole file (start line 1) and
// a git/github diff chunk is a hunk segment (start line = the hunk's first
// line), so base + newlines-before-match yields the true absolute line for
// every source that carries one. Sources without a line concept (slack, s3,
// gcs, stdin, siem, ...) are returned unchanged. The copy is shallow — Data
// and every other metadata pointer are shared; only the one line-bearing
// sub-struct is duplicated so per-finding lines never race on the shared
// chunk.
func chunkWithMatchLine(c *sources.Chunk, raw []byte) *sources.Chunk {
	if c == nil {
		return c
	}
	md := &c.SourceMetadata
	switch {
	case md.Filesystem != nil:
		if line := computeLineFromMatch(c.Data, raw, md.Filesystem.Line); line > 0 {
			cp := *c
			m := *md.Filesystem
			m.Line = line
			cp.SourceMetadata.Filesystem = &m
			return &cp
		}
	case md.Git != nil:
		if line := computeLineFromMatch(c.Data, raw, md.Git.Line); line > 0 {
			cp := *c
			m := *md.Git
			m.Line = line
			cp.SourceMetadata.Git = &m
			return &cp
		}
	case md.GitHub != nil:
		if line := computeLineFromMatch(c.Data, raw, md.GitHub.Line); line > 0 {
			cp := *c
			m := *md.GitHub
			m.Line = line
			cp.SourceMetadata.GitHub = &m
			return &cp
		}
	case md.Forge != nil:
		if line := computeLineFromMatch(c.Data, raw, md.Forge.Line); line > 0 {
			cp := *c
			m := *md.Forge
			m.Line = line
			cp.SourceMetadata.Forge = &m
			return &cp
		}
	case md.SQLDump != nil:
		if line := computeLineFromMatch(c.Data, raw, md.SQLDump.Line); line > 0 {
			cp := *c
			m := *md.SQLDump
			m.Line = line
			cp.SourceMetadata.SQLDump = &m
			return &cp
		}
	case md.DockerImage != nil:
		if line := computeLineFromMatch(c.Data, raw, md.DockerImage.Line); line > 0 {
			cp := *c
			m := *md.DockerImage
			m.Line = line
			cp.SourceMetadata.DockerImage = &m
			return &cp
		}
	}
	return c
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
// variant — and matches the lowercasing done at engine construction
// over keyword sets.
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
