// Package engine drives chunk dispatch, detector execution, and sink emission.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
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
	// RawSpan is the absolute byte span of Result.Raw in a replayable raw
	// source. Buffered findings leave it nil and retain the historical
	// Chunk.Data lookup in output formatters.
	RawSpan *[2]int
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
	// MinimumVerificationAssurance limits remote verification to detectors
	// whose audited policy can satisfy this assurance level. The zero value
	// preserves the legacy behaviour of attempting every verifier.
	//
	// This is an execution policy, not only an output filter: strict callers
	// must not pay for or trigger unaudited verification requests whose
	// findings would be discarded afterward.
	MinimumVerificationAssurance detectors.VerificationAssurance
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
	verificationAssurance []detectors.VerificationAssurance
	wantsFull             []bool
	prefilter             *ahocorasick.Matcher
	detectorIdxByPattern  [][]int
	lowerBufPool          sync.Pool
	sink                  Sink
	verificationCache     *verificationCache
	verificationFlights   singleflight.Group
	stats                 statsCounters
	failureMu             sync.Mutex
	failures              []ScanFailure
	failureTotal          int
	failureCounts         map[FailureKind]int
}

type streamMatch struct {
	offset       int64
	newlineCount int
	found        bool
}

type streamMatchCache struct {
	reader io.ReaderAt
	size   int64
	values map[string]streamMatch
}

func newStreamMatchCache(reader io.ReaderAt, size int64) *streamMatchCache {
	if reader == nil {
		return nil
	}
	return &streamMatchCache{reader: reader, size: size, values: make(map[string]streamMatch)}
}

func (c *streamMatchCache) match(ctx context.Context, raw []byte) (streamMatch, error) {
	if c == nil || len(raw) == 0 {
		return streamMatch{offset: -1}, nil
	}
	key := string(raw)
	if match, ok := c.values[key]; ok {
		return match, nil
	}
	offset, newlineCount, err := findReaderMatch(ctx, c.reader, c.size, raw)
	match := streamMatch{offset: offset, newlineCount: newlineCount, found: offset >= 0}
	if err == nil {
		c.values[key] = match
	}
	return match, err
}

type redactedArchiveCoverageError struct {
	cause error
}

func (e *redactedArchiveCoverageError) Error() string { return "archive expansion failed" }
func (e *redactedArchiveCoverageError) Unwrap() error { return e.cause }

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
	verificationAssurance := make([]detectors.VerificationAssurance, len(ordered))
	wantsFull := make([]bool, len(ordered))
	for i, d := range ordered {
		_, isVerifier[i] = d.(detectors.Verifier)
		verificationAssurance[i] = maxVerificationAssurance(d)
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
		verificationAssurance: verificationAssurance,
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
	// Keep chunk ownership at the source/worker hand-off. A buffered queue
	// lets each source worker retain a full chunk while workers are already
	// holding their own chunks, multiplying peak RSS for large files.
	ch := make(chan *sources.Chunk)

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
	if c == nil {
		return
	}
	if c.Open != nil {
		e.scanOpenedChunk(ctx, c)
		return
	}
	if archive.LooksLikeArchive(c.Data) {
		e.scanArchive(ctx, c, 5*time.Second)
		return
	}
	e.scanChunkLeaf(ctx, c, "")
}

// scanOpenedChunk keeps large source bodies replayable instead of retaining a
// byte slice in the source queue. The opener owns admission checks (for
// example binary sniffing); the engine owns the returned closer until all
// decoder variants and detector passes have completed.
func (e *Engine) scanOpenedChunk(ctx context.Context, c *sources.Chunk) {
	reader, closer, size, err := c.Open(ctx)
	if closer != nil {
		defer func() {
			if closeErr := closer.Close(); closeErr != nil && ctx.Err() == nil {
				e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: closeErr})
			}
		}()
	}
	if err != nil {
		if ctx.Err() == nil {
			e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: err})
		}
		return
	}
	if reader == nil {
		// A nil reader with no error is the source's explicit skip result.
		return
	}
	if size < 0 {
		if ctx.Err() == nil {
			e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: errors.New("source returned a negative body size")})
		}
		return
	}

	isArchive, err := readerLooksLikeArchive(reader, size)
	if err != nil {
		if ctx.Err() == nil {
			e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: err})
		}
		return
	}
	if isArchive {
		// SectionReader supplies the archive walker a bounded view of the
		// source's replayable body without copying the outer archive.
		e.scanArchiveReader(ctx, c, io.NewSectionReader(reader, 0, size), size, 5*time.Second)
		return
	}
	e.scanChunkLeafReader(ctx, c, "", reader, size)
}

func readerLooksLikeArchive(reader io.ReaderAt, size int64) (bool, error) {
	if size == 0 {
		return false, nil
	}
	n := size
	if n > 512 {
		n = 512
	}
	prefix := make([]byte, int(n))
	got, err := reader.ReadAt(prefix, 0)
	if err != nil && !(errors.Is(err, io.EOF) && got == len(prefix)) {
		return false, fmt.Errorf("read archive prefix: %w", err)
	}
	if got != len(prefix) {
		return false, io.ErrUnexpectedEOF
	}
	return archive.LooksLikeArchive(prefix), nil
}

// scanArchive visits one validated leaf at a time. The expansion budget excludes
// detector/verification time, as it did when expansion preceded all detection.
func (e *Engine) scanArchive(ctx context.Context, c *sources.Chunk, budget time.Duration) {
	e.scanArchiveReader(ctx, c, bytes.NewReader(c.Data), int64(len(c.Data)), budget)
}

func (e *Engine) scanArchiveReader(ctx context.Context, c *sources.Chunk, input io.Reader, size int64, budget time.Duration) {
	archiveCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	started := time.Now()
	timer := time.AfterFunc(budget, func() { cancel(context.DeadlineExceeded) })
	defer timer.Stop()
	err := archive.WalkStreamContext(archiveCtx, archiveRootName(c), input, size, archive.Limits{
		MaxDepth: 3, MaxEntryBytes: 10 << 20, MaxExpandedBytes: 50 << 20, MaxFiles: 1000,
	}, func(entry archive.StreamEntry) error {
		if entry.Size < 0 || entry.Size > int64(^uint(0)>>1) {
			return fmt.Errorf("archive entry %q has invalid size %d", entry.Path, entry.Size)
		}
		if !timer.Stop() {
			return context.DeadlineExceeded
		}
		budget -= time.Since(started)
		if budget <= 0 {
			return context.DeadlineExceeded
		}
		inner := *c
		inner.Open = nil
		if readerAt, ok := entry.Reader.(io.ReaderAt); ok {
			if entry.Size <= archiveBufferedLeafThreshold {
				data, readErr := readReaderAt(ctx, readerAt, entry.Size)
				if readErr != nil {
					return readErr
				}
				inner.Data = data
				e.scanChunkLeaf(ctx, &inner, entry.Path)
			} else {
				// archive's spool reader is a bytes.Reader or SectionReader. Keep
				// large replayable leaves on disk/memory where the archive walker
				// put them, rather than copying them into a second body.
				inner.Data = nil
				e.scanChunkLeafReader(ctx, &inner, entry.Path, readerAt, entry.Size)
			}
		} else {
			data := make([]byte, entry.Size)
			if _, err := io.ReadFull(entry.Reader, data); err != nil {
				return err
			}
			inner.Data = data
			e.scanChunkLeaf(ctx, &inner, entry.Path)
		}
		started = time.Now()
		timer.Reset(budget)
		return ctx.Err()
	})
	if err != nil {
		if cause := context.Cause(archiveCtx); cause != nil {
			err = errors.Join(err, cause)
		}
		e.recordFailure(ScanFailure{
			Kind: FailureArchive, Source: archiveFailureSource(c),
			Err: &redactedArchiveCoverageError{cause: err},
		})
	}
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
	case md.S3 != nil:
		return md.S3.Key
	}
	return c.SourceName
}

// archiveFailureSource keeps user-visible coverage diagnostics safe without
// changing archiveRootName, which remains finding provenance.
func archiveFailureSource(c *sources.Chunk) string {
	if c != nil && c.SourceMetadata.S3 != nil {
		sum := sha256.Sum256([]byte(c.SourceMetadata.S3.Key))
		return fmt.Sprintf("s3-object-sha256:%x", sum)
	}
	return archiveRootName(c)
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
	// Keep archive leaves at or below the filesystem source's 1 MiB lazy-open
	// cutoff on the historical buffered path. Small members are cheaper to
	// scan from one byte slice than to create a decoder/read-window pipeline.
	archiveBufferedLeafThreshold = 1 << 20
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

	// Reuse the lowercase buffer across windows and chunks.
	lowerPtr := e.lowerBufPool.Get().(*[]byte)
	defer e.lowerBufPool.Put(lowerPtr)

	// Decode once per chunk before slicing windows. Decoding each raw window
	// independently resets base64/hex run alignment at every boundary and can
	// lose a credential that starts in an earlier window. The decoded variants
	// are already owned for the duration of this loop, so detector results do
	// not need the old scratch-buffer clone path.
	variants := decoder.Variants(c.Data)
	for _, v := range variants {
		if ctx.Err() != nil {
			return
		}
		e.runFullChunkDetectors(ctx, c, v, archivePath)
		e.scanVariantWindows(ctx, c, v, archivePath, lowerPtr)
	}
}

// scanChunkLeafReader is the replayable-input equivalent of
// scanChunkLeaf. WalkVariants keeps raw and decoded representations alive
// only for the callback, and each callback scans bounded windows directly
// from its ReaderAt. No source-sized byte slice is created here.
func (e *Engine) scanChunkLeafReader(ctx context.Context, c *sources.Chunk, archivePath string, reader io.ReaderAt, size int64) {
	e.stats.chunks.Add(1)
	e.stats.bytes.Add(size)
	if e.prefilter == nil {
		return
	}

	lowerPtr := e.lowerBufPool.Get().(*[]byte)
	defer e.lowerBufPool.Put(lowerPtr)
	windowBuf := make([]byte, maxWindowSize)
	matchCache := newStreamMatchCache(reader, size)
	err := decoder.WalkVariants(ctx, reader, size, func(source string, variant io.ReaderAt, variantSize int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.runFullChunkReaderDetectors(ctx, c, source, variant, variantSize, archivePath, matchCache); err != nil {
			return err
		}
		return e.scanVariantWindowsReader(ctx, c, source, variant, variantSize, archivePath, lowerPtr, windowBuf, matchCache)
	})
	if err != nil && ctx.Err() == nil {
		e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: err})
	}
}

// scanVariantWindowsReader feeds the same dispatch path used by buffered
// chunks, but reuses one bounded window buffer. Stream line and span metadata
// are resolved against the raw reader, so overlapping windows need no line
// bookkeeping of their own.
func (e *Engine) scanVariantWindowsReader(ctx context.Context, c *sources.Chunk, source string, reader io.ReaderAt, size int64, archivePath string, lowerPtr *[]byte, windowBuf []byte, matchCache *streamMatchCache) error {
	if size == 0 {
		return nil
	}
	if int64(len(windowBuf)) < min(size, int64(maxWindowSize)) {
		return errors.New("engine: stream window buffer is too small")
	}
	for start := int64(0); start < size; start += windowStepSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		windowSize := min(int64(len(windowBuf)), size-start)
		window := windowBuf[:int(windowSize)]
		n, err := reader.ReadAt(window, start)
		if err != nil && !(errors.Is(err, io.EOF) && n == len(window)) {
			return fmt.Errorf("read %s variant at %d: %w", sourceName(source), start, err)
		}
		if n != len(window) {
			return fmt.Errorf("read %s variant at %d: got %d bytes, want %d", sourceName(source), start, n, len(window))
		}
		v := decoder.Variant{Source: source, Data: window}
		e.dispatchAt(ctx, c, v, archivePath, lowerPtr, true, matchCache)
		if start+windowSize == size {
			break
		}
	}
	return nil
}

func sourceName(source string) string {
	if source == "" {
		return "raw"
	}
	return source
}

// runFullChunkDetectors dispatches every detector that opted in via
// FullChunkDetector against the whole chunk in one pass — bypassing
// both the windowing loop and the vicinity-slice dispatch. The
// scanVariantWindows path then SKIPs these detectors, so each
// FullChunk detector emits exactly once per chunk regardless of how
// many windows the chunk is split into.
func (e *Engine) runFullChunkDetectors(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string) {
	if !slices.Contains(e.wantsFull, true) {
		return
	}
	// FullChunkDetector opt-ins see every whole-chunk decoded variant once.
	// The window path below skips these detectors, preserving the previous
	// exactly-once-per-variant contract.
	for di := range e.dets {
		if !e.wantsFull[di] {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		e.runDetectorOn(ctx, c, v, archivePath, di, v.Data)
	}
}

func (e *Engine) runFullChunkReaderDetectors(ctx context.Context, c *sources.Chunk, source string, reader io.ReaderAt, size int64, archivePath string, matchCache *streamMatchCache) error {
	if !slices.Contains(e.wantsFull, true) {
		return nil
	}
	variant := decoder.Variant{Source: source}
	for di, d := range e.dets {
		if !e.wantsFull[di] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		var (
			results []detectors.Result
			err     error
		)
		verify := e.readerDetectorVerify(di)
		verifyStarted := time.Now()
		switch rd := d.(type) {
		case detectors.ReaderDetector:
			if verify && e.isVerifier[di] {
				// ReaderDetector has no byte-slice verification-cache route;
				// preserve the existing bypass accounting while keeping the
				// source body bounded.
				e.stats.verificationCacheBypasses.Add(1)
			}
			results, err = rd.FromReader(ctx, verify, reader, size)
		default:
			// External FullChunkDetector implementations may not have adopted
			// the optional stream method. Keep their exact FromData semantics;
			// this is a bounded compatibility fallback for source limits.
			data, readErr := readReaderAt(ctx, reader, size)
			if readErr != nil {
				return readErr
			}
			e.runDetectorOnAt(ctx, c, variant, archivePath, di, data, true, matchCache)
			continue
		}
		if verify && e.isVerifier[di] {
			e.stats.verifiedDetectorCalls.Add(1)
			e.stats.verifiedDetectorCallNanos.Add(time.Since(verifyStarted).Nanoseconds())
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			e.recordFailure(ScanFailure{Kind: FailureDetector, Source: archiveFailureSource(c), Detector: d.Type(), Err: err})
			continue
		}

		for _, result := range results {
			e.emitDetectorResult(ctx, c, variant, archivePath, di, true, result, matchCache)
		}
	}
	return nil
}

func (e *Engine) readerDetectorVerify(di int) bool {
	verify := !e.opts.NoVerify
	if minimum := e.opts.MinimumVerificationAssurance; verify && minimum != detectors.AssuranceUnknown {
		verify = e.verificationAssurance[di] >= minimum
	}
	return verify
}

func readReaderAt(ctx context.Context, reader io.ReaderAt, size int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 0 || uint64(size) > uint64(^uint(0)>>1) {
		return nil, errors.New("engine: replayable body exceeds addressable memory")
	}
	data := make([]byte, int(size))
	if len(data) == 0 {
		return data, nil
	}
	n, err := reader.ReadAt(data, 0)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(data)) {
		return nil, err
	}
	if n != len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

// scanVariantWindows dispatches one already-decoded variant in bounded
// windows. Keeping decoder state outside this loop preserves encoded-run
// alignment while retaining the regex work bound for large variants.
func (e *Engine) scanVariantWindows(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, lowerPtr *[]byte) {
	data := v.Data
	if len(data) <= maxWindowSize {
		e.dispatch(ctx, c, v, archivePath, lowerPtr)
		return
	}
	for start := 0; start < len(data); start += windowStepSize {
		if ctx.Err() != nil {
			return
		}
		end := start + maxWindowSize
		if end > len(data) {
			end = len(data)
		}
		window := v
		window.Data = data[start:end]
		e.dispatch(ctx, c, window, archivePath, lowerPtr)
		if end == len(data) {
			break
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
func (e *Engine) dispatch(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, lowerPtr *[]byte) {
	e.dispatchAt(ctx, c, v, archivePath, lowerPtr, false, nil)
}

func (e *Engine) dispatchAt(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, lowerPtr *[]byte, stream bool, matchCache *streamMatchCache) {
	lower := lowerCaseInto((*lowerPtr)[:0], v.Data)
	*lowerPtr = lower
	// Group hits by detector: each detector sees the union of its
	// keyword-hit vicinities. Accumulate start/end byte ranges per
	// detector, merge overlapping ranges, then run FromData once per
	// merged range. VisitHits preserves the global input order while
	// avoiding an unbounded hit slice on repeated keywords.
	var dets map[int][]vicinitySpan
	var detectorOrder []int
	e.prefilter.VisitHits(lower, func(h ahocorasick.Hit) {
		for _, di := range e.detectorIdxByPattern[h.PatternID] {
			// FullChunkDetector opt-ins are handled once per chunk
			// by runFullChunkDetectors. Skip them here so they don't
			// also fire per window — the regex would emit duplicate
			// findings into dedup.
			if e.wantsFull[di] {
				continue
			}
			if dets == nil {
				dets = make(map[int][]vicinitySpan)
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
			// Hits arrive in byte order, so merge each detector's spans as
			// they arrive instead of allocating and sorting every occurrence.
			spans := dets[di]
			if len(spans) > 0 && start <= spans[len(spans)-1].end {
				if end > spans[len(spans)-1].end {
					spans[len(spans)-1].end = end
				}
			} else {
				dets[di] = append(spans, vicinitySpan{start, end})
			}
		}
	})
	sort.Ints(detectorOrder)
	for _, di := range detectorOrder {
		spans := dets[di]
		// Bail out of the per-detector dispatch on cancellation so a
		// cancelled scan stops running detectors mid-window.
		if ctx.Err() != nil {
			return
		}
		for _, sp := range spans {
			e.runDetectorOnAt(ctx, c, v, archivePath, di, v.Data[sp.start:sp.end], stream, matchCache)
		}
	}
}

type vicinitySpan struct{ start, end int }

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
	e.runDetectorOnAt(ctx, c, v, archivePath, di, data, false, nil)
}

func (e *Engine) runDetectorOnAt(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, data []byte, stream bool, matchCache *streamMatchCache) {
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
			e.recordFailure(ScanFailure{Kind: FailureDetector, Source: archiveFailureSource(c), Detector: d.Type(), Err: err})
		}
		return
	}
	for _, r := range results {
		e.emitDetectorResult(ctx, c, v, archivePath, di, stream, r, matchCache)
	}
}

func (e *Engine) emitDetectorResult(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, stream bool, r detectors.Result, matchCache *streamMatchCache) {
	d := e.dets[di]
	if stream {
		// Stream windows are reused for every subsequent ReadAt. Detectors are
		// allowed to return slices into their input, so findings must own their
		// secret bytes before the next window overwrites that buffer.
		r.Raw = bytes.Clone(r.Raw)
		r.RawV2 = bytes.Clone(r.RawV2)
	}
	if v.Source != "" {
		if r.ExtraData == nil {
			r.ExtraData = map[string]string{}
		}
		r.ExtraData["decoded_from"] = v.Source
	}
	applyVerificationPolicy(d, &r)
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
	line := 0
	if stream {
		// Preserve the source's original line when a detector normalizes Raw
		// and that value cannot be located in the raw body.
		line = sourceLine(c)
	}
	var (
		cachedMatch streamMatch
		matchErr    error
	)
	if stream && matchCache != nil && len(r.Raw) > 0 {
		cachedMatch, matchErr = matchCache.match(ctx, r.Raw)
		if matchErr == nil && cachedMatch.found && hasSourceLine(c) {
			base := sourceLine(c)
			if base <= 0 {
				base = 1
			}
			line = base + cachedMatch.newlineCount
		}
	}
	chunk := chunkWithMatchLine(c, r.Raw)
	if stream {
		chunk = chunkForFinding(c, line, true)
	}
	var rawSpan *[2]int
	if stream && matchCache != nil && len(r.Raw) > 0 {
		if matchErr != nil {
			if ctx.Err() == nil {
				e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: matchErr})
			}
		} else if cachedMatch.found && uint64(cachedMatch.offset) <= uint64(^uint(0)>>1)-uint64(len(r.Raw)) {
			start := int(cachedMatch.offset)
			rawSpan = &[2]int{start, start + len(r.Raw)}
		}
	}
	e.sink.Emit(Finding{
		Result:         r,
		Chunk:          chunk,
		Detector:       d.Type(),
		VerifierBacked: e.isVerifier[di],
		RawSpan:        rawSpan,
	})
}

func applyVerificationPolicy(detector detectors.Detector, result *detectors.Result) {
	if !result.Verified {
		return
	}
	maxAssurance := maxVerificationAssurance(detector)
	if result.VerificationAssurance == detectors.AssuranceUnknown && maxAssurance != detectors.AssuranceUnknown {
		result.VerificationAssurance = maxAssurance
		return
	}
	if result.VerificationAssurance <= maxAssurance {
		return
	}
	claimed := result.VerificationAssurance
	result.Verified = false
	result.VerificationAssurance = maxAssurance
	result.VerificationErr = errors.Join(
		result.VerificationErr,
		fmt.Errorf("verification assurance %s exceeds detector policy %s", claimed, maxAssurance),
	)
}

func maxVerificationAssurance(detector detectors.Detector) detectors.VerificationAssurance {
	policy, ok := detector.(detectors.VerificationPolicy)
	if !ok {
		return detectors.AssuranceUnknown
	}
	maxAssurance := policy.MaxVerificationAssurance()
	if maxAssurance > detectors.AssuranceProviderConfirmed {
		return detectors.AssuranceUnknown
	}
	return maxAssurance
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

func hasSourceLine(c *sources.Chunk) bool {
	if c == nil {
		return false
	}
	md := c.SourceMetadata
	return md.Filesystem != nil || md.Git != nil || md.GitHub != nil || md.Forge != nil || md.SQLDump != nil || md.DockerImage != nil
}

func sourceLine(c *sources.Chunk) int {
	if c == nil {
		return 0
	}
	md := c.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Line
	case md.Git != nil:
		return md.Git.Line
	case md.GitHub != nil:
		return md.GitHub.Line
	case md.Forge != nil:
		return md.Forge.Line
	case md.SQLDump != nil:
		return md.SQLDump.Line
	case md.DockerImage != nil:
		return md.DockerImage.Line
	default:
		return 0
	}
}

// findReaderMatch returns the first raw match and the number of newlines
// before it. It deliberately overlaps adjacent ReadAt calls so a result that
// crosses a buffer boundary has the same first-occurrence semantics as
// bytes.Index on the historical whole-chunk path.
func findReaderMatch(ctx context.Context, reader io.ReaderAt, size int64, raw []byte) (int64, int, error) {
	if len(raw) == 0 || size == 0 {
		return -1, 0, nil
	}
	const blockSize = 64 << 10
	block := blockSize
	if len(raw)+1 > block {
		block = len(raw) + 1
	}
	buf := make([]byte, block)
	var lineCount int
	for start := int64(0); start < size; {
		if err := ctx.Err(); err != nil {
			return -1, 0, err
		}
		want := int64(len(buf))
		if remaining := size - start; remaining < want {
			want = remaining
		}
		got, err := reader.ReadAt(buf[:int(want)], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return -1, 0, err
		}
		if got != int(want) {
			return -1, 0, io.ErrUnexpectedEOF
		}
		idx := bytes.Index(buf[:got], raw)
		if idx >= 0 {
			return start + int64(idx), lineCount + bytes.Count(buf[:idx], []byte{'\n'}), nil
		}
		if got < len(raw) {
			return -1, 0, nil
		}
		overlap := len(raw) - 1
		if overlap > got {
			overlap = got
		}
		advance := got - overlap
		lineCount += bytes.Count(buf[:advance], []byte{'\n'})
		start += int64(advance)
		if err != nil && start >= size {
			return -1, 0, nil
		}
	}
	return -1, 0, nil
}

// chunkForFinding detaches a replayable stream body before publishing a
// finding. The opener may close immediately after the worker returns, and
// retaining it in a sink would make a finding unexpectedly reopen a path.
// Stream findings intentionally leave Data nil; a later output layer can use
// an explicit offset without retaining a source-sized or window-sized body.
func chunkForFinding(c *sources.Chunk, line int, stream bool) *sources.Chunk {
	if c == nil || !stream {
		return c
	}
	cp := *c
	cp.Data = nil
	cp.Open = nil
	setChunkLine(&cp, line)
	return &cp
}

func setChunkLine(c *sources.Chunk, line int) {
	if c == nil || line <= 0 {
		return
	}
	md := &c.SourceMetadata
	switch {
	case md.Filesystem != nil:
		m := *md.Filesystem
		m.Line = line
		md.Filesystem = &m
	case md.Git != nil:
		m := *md.Git
		m.Line = line
		md.Git = &m
	case md.GitHub != nil:
		m := *md.GitHub
		m.Line = line
		md.GitHub = &m
	case md.Forge != nil:
		m := *md.Forge
		m.Line = line
		md.Forge = &m
	case md.SQLDump != nil:
		m := *md.SQLDump
		m.Line = line
		md.SQLDump = &m
	case md.DockerImage != nil:
		m := *md.DockerImage
		m.Line = line
		md.DockerImage = &m
	}
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
