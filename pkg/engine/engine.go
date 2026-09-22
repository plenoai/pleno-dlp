// Package engine drives chunk dispatch, detector execution, and sink emission.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
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
	// rawHint is the position where Result.Raw was observed in a raw-variant
	// stream window. It is used only after raw observation has been enabled;
	// the authoritative reader remains the fallback for every other finding.
	rawHint streamRawHint
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

type streamRawHint struct {
	offset   int64
	newlines int
	ok       bool
}

type streamWindowBase struct {
	offset   int64
	newlines int
	ok       bool
}

type streamMatchCache struct {
	reader  io.ReaderAt
	size    int64
	values  map[string]streamMatch
	pending *streamFindingBatch
	// firstPair and restPair are populated only after enough distinct raw
	// candidates make the observation pass worthwhile. They prove whether a
	// hinted two-byte raw has an earlier occurrence without retaining source
	// windows or rescanning the reader for each candidate. firstPair stays a
	// sparse map because active caches usually see only a small prefix set.
	firstPair    map[uint16]int64
	restPair     map[uint16][]int64
	restPairFull *[65536]bool
	// observationCandidates stays bounded until observation is enabled. A
	// single raw therefore uses the ordinary shared scan and retains no fixed
	// prefix table.
	observationCandidates map[string]struct{}
	observationActive     bool
	observationDisabled   bool
	observationThrough    int64
	// pairIndex and byteIndex hold complete prefix-position indexes built
	// lazily for prefixes shared by a dense batch. All indexes a batch needs
	// are computed in one shared forward pass and reused for every later
	// batch, so position resolution stays proportional to the input, not to
	// the batch or prefix count.
	pairIndex map[uint16]*streamPrefixIndex
	byteIndex map[byte]*streamPrefixIndex
	// indexGroupRawCounts tracks distinct short raws seen for each prefix
	// across flushes. It lets a group that arrives in several small batches
	// earn one reusable index without indexing a one-result group.
	indexGroupRawCounts map[uint32]int
	// indexOOM marks prefixes that exhaust the shared position budget
	// (key bit 16 distinguishes single-byte prefixes);
	// those keep the per-batch shared scan.
	indexOOM map[uint32]bool
	// indexedPositions and indexSampleBytes bound the metadata and sample
	// payloads retained across all cached indexes and builds — they are
	// persistent counters, not per-build, so later builds cannot restart
	// the budget while earlier indexes stay cached.
	indexedPositions int64
	indexSampleBytes int64
}

// streamPrefixIndex is a complete index of one prefix's occurrences in the
// input: absolute positions, the number of newlines preceding each, and a
// short content sample captured during the build pass. Samples let raw
// verification run in memory — later batches resolve without any reader
// calls — while positions and newlines keep the authoritative ordering and
// line attribution. It is built only for prefixes a pending batch actually
// needs, so its memory stays proportional to the occurrences of requested
// prefixes, not the input.
type streamPrefixIndex struct {
	positions []int64
	newlines  []int
	samples   [][]byte // leading-position content samples; later positions verify via ReadAt
}

// streamPrefixIndexTotalCap bounds the positions retained across ALL cached
// prefix indexes and in-flight builds — slice headers and growth are
// per-position costs, so the budget is on entries, not payload bytes.
// Exhaustion marks the pending keys OOM and they keep the bounded shared
// scan instead.
const streamPrefixIndexTotalCap = 1 << 20

// streamPrefixIndexSampleLen is how many leading bytes of content each index
// entry stores for in-memory verification.
const streamPrefixIndexSampleLen = 64

// streamPrefixIndexSampleBytes bounds samples across all cached indexes.
// Positions past the budget verify with a targeted ReadAt. Samples remain
// a contiguous prefix of each index because the budget only grows per build.
const streamPrefixIndexSampleBytes = 8 << 20

func newStreamMatchCache(reader io.ReaderAt, size int64) *streamMatchCache {
	if reader == nil {
		return nil
	}
	return &streamMatchCache{reader: reader, size: size, values: make(map[string]streamMatch)}
}

// streamRawObservationMinCandidates amortizes the one-time bootstrap scan
// and bounded prefix table over distinct raw candidates. Sparse one-result
// files use the shared reader scan and avoid this retained state entirely.
const streamRawObservationMinCandidates = 8

// observeRawWindow records two-byte positions for one raw source window.
// Callers use it only after observation is enabled, except focused tests that
// deliberately exercise the candidate proof path. Repeated overlapping
// windows advance from the last recorded byte so each position is indexed
// once.
func (c *streamMatchCache) observeRawWindow(source string, data []byte, start int64) {
	if c == nil || source != "" || len(data) == 0 {
		return
	}
	if c.firstPair == nil {
		c.firstPair = make(map[uint16]int64)
		c.restPairFull = &[65536]bool{}
	}
	from := 0
	if start < c.observationThrough {
		from = int(c.observationThrough - start)
		if from >= len(data) {
			return
		}
		if from > 0 {
			from--
		}
	}
	for i := from; i < len(data); i++ {
		if i+1 >= len(data) {
			break
		}
		pos := start + int64(i) + 1
		b := data[i]
		pair := uint16(b)<<8 | uint16(data[i+1])
		if (*c.restPairFull)[pair] {
			continue
		}
		if _, ok := c.firstPair[pair]; !ok {
			c.firstPair[pair] = pos
		} else {
			if c.restPair == nil {
				c.restPair = make(map[uint16][]int64)
			}
			rest := append(c.restPair[pair], pos)
			c.restPair[pair] = rest
			if len(rest) >= hintVerifyCandidateCap {
				(*c.restPairFull)[pair] = true
			}
		}
	}
	if end := start + int64(len(data)); end > c.observationThrough {
		c.observationThrough = end
	}
}

// hintVerifyCandidateCap bounds how many recorded prefix positions a single
// hint verification reads back. Dense prefixes escalate to the complete
// index/shared scan instead of per-candidate random reads.
const hintVerifyCandidateCap = 64

// observeRawCandidate enables hint tracking after enough distinct raw values
// have appeared in the undecoded source. It bootstraps the bytes before the
// current window exactly once, so a later hint never treats an unobserved
// earlier source position as absent.
func (c *streamMatchCache) observeRawCandidate(ctx context.Context, data []byte, start int64, raw []byte) error {
	if c == nil || len(raw) == 0 || c.observationDisabled {
		return nil
	}
	if c.observationActive {
		c.observeRawWindow("", data, start)
		return nil
	}
	if c.observationCandidates == nil {
		c.observationCandidates = make(map[string]struct{}, streamRawObservationMinCandidates)
	}
	c.observationCandidates[string(raw)] = struct{}{}
	if len(c.observationCandidates) < streamRawObservationMinCandidates {
		return nil
	}
	if err := c.bootstrapRawObservation(ctx, min(c.size, start+1)); err != nil {
		c.firstPair = nil
		c.restPair = nil
		c.restPairFull = nil
		c.observationThrough = 0
		c.observationCandidates = nil
		c.observationDisabled = true
		return err
	}
	c.observationActive = true
	c.observationCandidates = nil
	c.observeRawWindow("", data, start)
	return nil
}

func (c *streamMatchCache) bootstrapRawObservation(ctx context.Context, end int64) error {
	if end <= 0 {
		return nil
	}
	const blockSize = 64 << 10
	buffer := make([]byte, blockSize+1)
	for start := int64(0); start < end; {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining := end - start; remaining < want {
			want = remaining
		}
		got, err := c.reader.ReadAt(buffer[:int(want)], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if got != int(want) {
			return io.ErrUnexpectedEOF
		}
		c.observeRawWindow("", buffer[:got], start)
		advance := int64(got)
		if start+advance < end {
			advance--
		}
		start += advance
	}
	return nil
}

// prefixKey identifies a raw's search prefix: two bytes for raws of two or
// more bytes, a single byte for one-byte raws.
func prefixKey(raw []byte) (uint16, bool) {
	if len(raw) >= 2 {
		return uint16(raw[0])<<8 | uint16(raw[1]), false
	}
	if len(raw) == 1 {
		return uint16(raw[0]), true
	}
	return 0, false
}

// prefixLookup resolves a raw from its detector-window hint when the
// observed two-byte prefix has only a bounded number of earlier positions.
// A saturated prefix is delegated to its complete index; callers can fall
// back to the shared reader scan when observation is unavailable or partial.
func (c *streamMatchCache) prefixLookup(ctx context.Context, raw []byte, hint streamRawHint) (streamMatch, bool, error) {
	if c == nil || !hint.ok || len(raw) < 2 || c.firstPair == nil {
		return streamMatch{}, false, nil
	}
	key, _ := prefixKey(raw)
	first, observed := c.firstPair[key]
	if !observed {
		return streamMatch{}, false, nil
	}
	rest := c.restPair[key]
	if len(rest) < hintVerifyCandidateCap {
		matchEarlier := func(pos int64) (bool, error) {
			if pos == 0 || pos-1 >= hint.offset || pos-1+int64(len(raw)) > c.size {
				return false, nil
			}
			buf := make([]byte, len(raw))
			got, err := c.reader.ReadAt(buf, pos-1)
			if err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
			if got != len(raw) {
				return false, io.ErrUnexpectedEOF
			}
			return bytes.Equal(buf, raw), nil
		}
		earlier, err := matchEarlier(first)
		if err != nil {
			return streamMatch{}, false, err
		}
		for _, pos := range rest {
			if earlier || pos-1 >= hint.offset {
				break
			}
			if err := ctx.Err(); err != nil {
				return streamMatch{}, false, err
			}
			earlier, err = matchEarlier(pos)
			if err != nil {
				return streamMatch{}, false, err
			}
		}
		if earlier {
			return streamMatch{}, false, nil
		}
		return streamMatch{offset: hint.offset, newlineCount: hint.newlines, found: true}, true, nil
	}
	indexes, err := c.prefixIndexes(ctx, []uint32{uint32(key)})
	if err != nil {
		return streamMatch{}, false, err
	}
	index := indexes[uint32(key)]
	if index == nil {
		return streamMatch{}, false, nil
	}
	for i, pos := range index.positions {
		if err := ctx.Err(); err != nil {
			return streamMatch{}, false, err
		}
		matched, err := c.indexMatchAt(index, i, pos, raw)
		if err != nil {
			return streamMatch{}, false, err
		}
		if matched {
			return streamMatch{offset: pos, newlineCount: index.newlines[i], found: true}, true, nil
		}
	}
	return streamMatch{offset: -1}, true, nil
}

func (c *streamMatchCache) indexMatchAt(index *streamPrefixIndex, i int, pos int64, raw []byte) (bool, error) {
	if i < len(index.samples) {
		if sample := index.samples[i]; sample != nil {
			if len(sample) >= len(raw) {
				return bytes.Equal(sample[:len(raw)], raw), nil
			}
			if !bytes.Equal(sample, raw[:len(sample)]) {
				return false, nil
			}
		}
	}
	if pos+int64(len(raw)) > c.size {
		return false, nil
	}
	buf := make([]byte, len(raw))
	got, err := c.reader.ReadAt(buf, pos)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if got != len(raw) {
		return false, io.ErrUnexpectedEOF
	}
	return bytes.Equal(buf, raw), nil
}

// indexCandidateAt returns the bytes for one raw length at an indexed
// position. All raws in the caller's group share prefix, so one sample/read
// can be looked up against every raw of that length.
func (c *streamMatchCache) indexCandidateAt(index *streamPrefixIndex, i int, pos int64, length int, prefix []byte, buf []byte) ([]byte, []byte, bool, error) {
	if length <= 0 {
		return nil, buf, false, nil
	}
	if i < len(index.samples) {
		if sample := index.samples[i]; sample != nil {
			if len(sample) >= length {
				return sample[:length], buf, true, nil
			}
			common := len(sample)
			if common > len(prefix) {
				common = len(prefix)
			}
			if common > 0 && !bytes.Equal(sample[:common], prefix[:common]) {
				return nil, buf, false, nil
			}
		}
	}
	if pos+int64(length) > c.size {
		return nil, buf, false, nil
	}
	if cap(buf) < length {
		buf = make([]byte, length)
	}
	buf = buf[:length]
	got, err := c.reader.ReadAt(buf, pos)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, buf, false, err
	}
	if got != length {
		return nil, buf, false, io.ErrUnexpectedEOF
	}
	return buf, buf, true, nil
}

// indexFor returns the cached complete index for a prefix key, or nil when
// the prefix has no index yet (or is marked OOM).
func (c *streamMatchCache) indexFor(oomKey uint32) *streamPrefixIndex {
	if oomKey&indexGroupSingleBit != 0 {
		return c.byteIndex[byte(oomKey)]
	}
	return c.pairIndex[uint16(oomKey)]
}

// prefixIndexes returns complete occurrence indexes for the given prefix
// keys. Indexes already built are reused; all missing ones are built in a
// single shared forward pass, so the reader is scanned at most once per call
// no matter how many distinct prefixes are saturated. When the combined
// position budget is exhausted, pending keys are marked OOM and their raws
// keep the bounded shared scan.
func (c *streamMatchCache) prefixIndexes(ctx context.Context, keys []uint32) (map[uint32]*streamPrefixIndex, error) {
	out := make(map[uint32]*streamPrefixIndex, len(keys))
	var missing []uint32
	for _, k := range keys {
		if index := c.indexFor(k); index != nil {
			out[k] = index
			continue
		}
		if c.indexOOM[k] {
			continue
		}
		missing = append(missing, k)
	}
	if len(missing) == 0 {
		return out, nil
	}
	built, err := c.scanPrefixIndexes(ctx, missing)
	if err != nil {
		return nil, err
	}
	if c.indexOOM == nil {
		c.indexOOM = make(map[uint32]bool)
	}
	for _, k := range missing {
		index := built[k]
		if index == nil {
			c.indexOOM[k] = true
			continue
		}
		if k&indexGroupSingleBit != 0 {
			if c.byteIndex == nil {
				c.byteIndex = make(map[byte]*streamPrefixIndex)
			}
			c.byteIndex[byte(k)] = index
		} else {
			if c.pairIndex == nil {
				c.pairIndex = make(map[uint16]*streamPrefixIndex)
			}
			c.pairIndex[uint16(k)] = index
		}
		out[k] = index
		c.indexedPositions += int64(len(index.positions))
	}
	return out, nil
}

// scanPrefixIndexes enumerates the occurrences of every requested prefix in
// one bounded forward pass, recording each absolute position and the number
// of newlines before it. Exhausting the shared position budget discards
// the pending build; cached indexes remain valid. Sample usage is committed
// only on success, so errors and cancellation leave the cache unchanged.
func (c *streamMatchCache) scanPrefixIndexes(ctx context.Context, oomKeys []uint32) (map[uint32]*streamPrefixIndex, error) {
	singles := make(map[byte]uint32, len(oomKeys))
	pairs := make(map[uint16]uint32, len(oomKeys))
	indexes := make(map[uint32]*streamPrefixIndex, len(oomKeys))
	for _, k := range oomKeys {
		indexes[k] = &streamPrefixIndex{}
		if k&indexGroupSingleBit != 0 {
			singles[byte(k)] = k
		} else {
			pairs[uint16(k)] = k
		}
	}
	var fastPair uint16
	var fastPairKey uint32
	fastPairScan := len(pairs) == 1 && len(singles) == 0
	if fastPairScan {
		for pair, key := range pairs {
			fastPair, fastPairKey = pair, key
		}
	}
	fastPairPattern := []byte{byte(fastPair >> 8), byte(fastPair)}
	var fastSingle byte
	var fastSingleKey uint32
	fastSingleScan := len(singles) == 1 && len(pairs) == 0
	if fastSingleScan {
		for single, key := range singles {
			fastSingle, fastSingleKey = single, key
		}
	}
	const blockSize = 64 << 10
	buffer := make([]byte, blockSize+1)
	var lineCount int
	var positionsThisBuild int64
	sampleBytes := c.indexSampleBytes
	budgetExceeded := func() bool {
		return c.indexedPositions+positionsThisBuild >= streamPrefixIndexTotalCap
	}
	dropAll := func() {
		for pending := range indexes {
			indexes[pending] = nil
		}
		sampleBytes = c.indexSampleBytes
	}
record:
	for start := int64(0); start < c.size; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := int64(len(buffer))
		if remaining := c.size - start; remaining < want {
			want = remaining
		}
		got, err := c.reader.ReadAt(buffer[:int(want)], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if got != int(want) {
			return nil, io.ErrUnexpectedEOF
		}
		data := buffer[:got]
		// The final byte of a non-final window is scanned again at the head
		// of the next window so a two-byte prefix spanning the boundary is
		// not missed.
		end := got
		if start+int64(got) < c.size {
			end = got - 1
		}
		if end <= 0 {
			break
		}
		if fastPairScan || fastSingleScan {
			searchEnd := end
			if fastPairScan && end < got {
				searchEnd++
			}
			var from, lineScan int
			lineAt := lineCount
			for {
				var relative int
				if fastPairScan {
					relative = bytes.Index(data[from:searchEnd], fastPairPattern)
				} else {
					relative = bytes.IndexByte(data[from:end], fastSingle)
				}
				if relative < 0 {
					break
				}
				j := from + relative
				for lineScan < j {
					if data[lineScan] == '\n' {
						lineAt++
					}
					lineScan++
				}
				if budgetExceeded() {
					dropAll()
					break record
				}
				key := fastPairKey
				if fastSingleScan {
					key = fastSingleKey
				}
				index := indexes[key]
				index.positions = append(index.positions, start+int64(j))
				index.newlines = append(index.newlines, lineAt)
				positionsThisBuild++
				if sampleBytes+streamPrefixIndexSampleLen <= streamPrefixIndexSampleBytes {
					sampleEnd := j + streamPrefixIndexSampleLen
					if sampleEnd > got {
						sampleEnd = got
					}
					sample := make([]byte, sampleEnd-j)
					copy(sample, data[j:sampleEnd])
					index.samples = append(index.samples, sample)
					sampleBytes += int64(len(sample))
				}
				lineScan = j
				from = j + 1
			}
			for lineScan < end {
				if data[lineScan] == '\n' {
					lineAt++
				}
				lineScan++
			}
			lineCount = lineAt
			start += int64(end)
			continue
		}
		for j := 0; j < end; j++ {
			pos := start + int64(j)
			b := data[j]
			if j+1 < got {
				if k, wanted := pairs[uint16(b)<<8|uint16(data[j+1])]; wanted && indexes[k] != nil {
					if budgetExceeded() {
						// Retained-position budget exhausted: every
						// pending key keeps the bounded shared scan.
						dropAll()
						break record
					}
					indexes[k].positions = append(indexes[k].positions, pos)
					indexes[k].newlines = append(indexes[k].newlines, lineCount)
					positionsThisBuild++
					if sampleBytes+streamPrefixIndexSampleLen <= streamPrefixIndexSampleBytes {
						end := j + streamPrefixIndexSampleLen
						if end > got {
							end = got
						}
						sample := make([]byte, end-j)
						copy(sample, data[j:end])
						indexes[k].samples = append(indexes[k].samples, sample)
						sampleBytes += int64(len(sample))
					}
				}
			}
			if k, wanted := singles[b]; wanted && indexes[k] != nil {
				if budgetExceeded() {
					dropAll()
					break record
				}
				indexes[k].positions = append(indexes[k].positions, pos)
				indexes[k].newlines = append(indexes[k].newlines, lineCount)
				positionsThisBuild++
				if sampleBytes+streamPrefixIndexSampleLen <= streamPrefixIndexSampleBytes {
					end := j + streamPrefixIndexSampleLen
					if end > got {
						end = got
					}
					sample := make([]byte, end-j)
					copy(sample, data[j:end])
					indexes[k].samples = append(indexes[k].samples, sample)
					sampleBytes += int64(len(sample))
				}
			}
			if b == '\n' {
				lineCount++
			}
		}
		start += int64(end)
	}
	c.indexSampleBytes = sampleBytes
	return indexes, nil
}

type streamFindingBatch struct {
	findings       []Finding
	resolveFailed  bool
	observationErr error
}

func (b *streamFindingBatch) append(finding Finding) {
	if b == nil {
		return
	}
	b.findings = append(b.findings, finding)
}

func (b *streamFindingBatch) flush(ctx context.Context, e *Engine, c *sources.Chunk, cache *streamMatchCache) {
	if b == nil || len(b.findings) == 0 {
		return
	}
	observationErr := b.observationErr
	b.observationErr = nil
	var resolveErr error
	if !b.resolveFailed {
		raws := make([][]byte, 0, len(b.findings))
		hints := make([]streamRawHint, 0, len(b.findings))
		for _, pending := range b.findings {
			raws = append(raws, pending.Result.Raw)
			hints = append(hints, pending.rawHint)
		}
		resolveErr = cache.resolve(ctx, raws, hints)
		if resolveErr != nil {
			b.resolveFailed = true
			if ctx.Err() == nil {
				e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: resolveErr})
			}
		}
	}
	if observationErr != nil && ctx.Err() == nil &&
		(resolveErr == nil || !errors.Is(resolveErr, observationErr)) {
		e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: observationErr})
	}
	for i := range b.findings {
		pending := &b.findings[i]
		raw := pending.Result.Raw
		if match, ok := cache.lookup(raw); ok && match.found {
			if hasSourceLine(pending.Chunk) {
				base := sourceLine(pending.Chunk)
				if base <= 0 {
					base = 1
				}
				pending.Chunk = chunkForFinding(pending.Chunk, base+match.newlineCount, true)
			}
			if uint64(match.offset) <= uint64(^uint(0)>>1)-uint64(len(raw)) {
				start := int(match.offset)
				pending.RawSpan = &[2]int{start, start + len(raw)}
			}
		}
		e.sink.Emit(*pending)
	}
	clear(b.findings)
	b.findings = b.findings[:0]
}

func (c *streamMatchCache) match(ctx context.Context, raw []byte, hint streamRawHint) (streamMatch, error) {
	if c == nil || len(raw) == 0 {
		return streamMatch{offset: -1}, nil
	}
	key := string(raw)
	if match, ok := c.values[key]; ok {
		return match, nil
	}
	if match, done, err := c.prefixLookup(ctx, raw, hint); err != nil {
		return streamMatch{offset: -1}, err
	} else if done {
		c.values[key] = match
		return match, nil
	}
	offset, newlineCount, err := findReaderMatch(ctx, c.reader, c.size, raw)
	match := streamMatch{offset: offset, newlineCount: newlineCount, found: offset >= 0}
	if err == nil {
		c.values[key] = match
	}
	return match, err
}

func (c *streamMatchCache) lookup(raw []byte) (streamMatch, bool) {
	if c == nil || len(raw) == 0 {
		return streamMatch{offset: -1}, false
	}
	match, ok := c.values[string(raw)]
	return match, ok
}

const streamBatchMaxRaw = 32 << 10

// Keep detector output bounded while retaining enough findings to resolve
// their raw spans in one pass. The cache survives each flush, so repeated raw
// values do not cause another source read; a reader failure also stops retrying
// for the rest of this variant after the first reported error.
// ponytail: diverse batches reread the source; raise this limit only when
// profiling shows those passes dominate and the extra pending memory fits.
const streamFindingBatchLimit = 1024

// A complete prefix index retains up to a million positions. A small group
// gets one ordinary shared scan instead; retain an index only when enough
// distinct raws can amortize that storage across the bounded batches.
const streamIndexGroupMinRaws = 64

// resolve finds all short, uncached raw values in one bounded forward pass.
// Long values keep the exact single-pattern fallback because making the block
// overlap as large as an arbitrary detector result would defeat the stream
// memory bound.
func (c *streamMatchCache) resolve(ctx context.Context, raws [][]byte, hints []streamRawHint) error {
	if c == nil {
		return nil
	}
	short := make(map[string]struct{}, len(raws))
	long := make([][]byte, 0)
	// indexGroups collects short raws that share a prefix densely enough to
	// amortize one complete prefix index. Smaller groups use one ordinary
	// shared scan, which avoids retaining an index for a single raw.
	indexGroups := make(map[uint32][]string)
	seenIndexRaws := make(map[string]struct{})
	newIndexGroupRawCounts := make(map[uint32]int)
	rawHints := make(map[string]streamRawHint, len(raws))
	for i, raw := range raws {
		if len(raw) == 0 {
			continue
		}
		key := string(raw)
		if _, ok := c.values[key]; ok {
			continue
		}
		if i < len(hints) {
			hint := hints[i]
			if previous, exists := rawHints[key]; !exists || (!previous.ok && hint.ok) {
				rawHints[key] = hint
			}
		}
		if len(raw) <= streamBatchMaxRaw {
			prefix, single := prefixKey(raw)
			groupKey := uint32(prefix)
			if single {
				groupKey |= indexGroupSingleBit
			}
			if _, seen := seenIndexRaws[key]; !seen {
				seenIndexRaws[key] = struct{}{}
				indexGroups[groupKey] = append(indexGroups[groupKey], key)
				newIndexGroupRawCounts[groupKey]++
			}
			continue
		}
		long = append(long, raw)
	}
	for groupKey, keys := range indexGroups {
		if c.indexGroupRawCounts[groupKey]+newIndexGroupRawCounts[groupKey] >= streamIndexGroupMinRaws || c.indexFor(groupKey) != nil {
			continue
		}
		for _, key := range keys {
			if c.prefixListFull([]byte(key)) {
				short[key] = struct{}{}
				continue
			}
			match, done, err := c.prefixLookup(ctx, []byte(key), rawHints[key])
			if err != nil {
				return err
			}
			if done {
				c.values[key] = match
			} else {
				short[key] = struct{}{}
			}
		}
		delete(indexGroups, groupKey)
	}
	if err := c.resolveIndexGroups(ctx, indexGroups, short); err != nil {
		return err
	}
	if err := findReaderMatches(ctx, c.reader, c.size, short, c.values); err != nil {
		return err
	}
	if len(newIndexGroupRawCounts) > 0 {
		if c.indexGroupRawCounts == nil {
			c.indexGroupRawCounts = make(map[uint32]int)
		}
		for groupKey, count := range newIndexGroupRawCounts {
			c.indexGroupRawCounts[groupKey] += count
		}
	}
	for _, raw := range long {
		if _, err := c.match(ctx, raw, rawHints[string(raw)]); err != nil {
			return err
		}
	}
	return nil
}

func (c *streamMatchCache) prefixListFull(raw []byte) bool {
	key, single := prefixKey(raw)
	if single || c == nil || c.firstPair == nil {
		return false
	}
	return len(c.restPair[key]) >= hintVerifyCandidateCap
}

// indexGroupSingleBit marks single-byte prefix keys inside the indexGroups
// map so they cannot collide with two-byte prefix keys whose high byte is 0.
const indexGroupSingleBit uint32 = 1 << 16

// resolveIndexGroups resolves every raw in each prefix group by walking that
// prefix's complete occurrence index once: at each indexed position the
// candidate bytes are compared against the whole group, so the group's reads
// stay proportional to the prefix's occurrence count rather than the product
// of positions and raws. Raws the index cannot place join the shared scan.
func (c *streamMatchCache) resolveIndexGroups(ctx context.Context, groups map[uint32][]string, short map[string]struct{}) error {
	groupKeys := make([]uint32, 0, len(groups))
	for groupKey := range groups {
		groupKeys = append(groupKeys, groupKey)
	}
	indexes, err := c.prefixIndexes(ctx, groupKeys)
	if err != nil {
		return err
	}
	for groupKey, keys := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		index := indexes[groupKey]
		if index == nil {
			for _, key := range keys {
				short[key] = struct{}{}
			}
			continue
		}
		lengthGroups := make(map[int]*streamRawGroup)
		lengths := make([]int, 0, len(keys))
		var prefix []byte
		for _, key := range keys {
			if prefix == nil {
				prefix = []byte(key)
			} else {
				prefix = commonPrefix(prefix, key)
			}
			length := len(key)
			lengthGroup := lengthGroups[length]
			if lengthGroup == nil {
				lengthGroup = &streamRawGroup{length: length, patterns: make(map[string]string)}
				lengthGroups[length] = lengthGroup
				lengths = append(lengths, length)
			}
			lengthGroup.patterns[key] = key
		}
		slices.Sort(lengths)
		var readBuffer []byte
		remaining := len(keys)
		for i, pos := range index.positions {
			if remaining == 0 {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, length := range lengths {
				lengthGroup := lengthGroups[length]
				candidate, buf, available, err := c.indexCandidateAt(index, i, pos, length, prefix, readBuffer)
				readBuffer = buf
				if err != nil {
					return err
				}
				if !available {
					continue
				}
				key, matched := lengthGroup.patterns[string(candidate)]
				if matched {
					if _, resolved := c.values[key]; resolved {
						continue
					}
					c.values[key] = streamMatch{offset: pos, newlineCount: int(index.newlines[i]), found: true}
					remaining--
				}
			}
		}
		for _, key := range keys {
			if _, resolved := c.values[key]; !resolved {
				// A complete index is authoritative: every occurrence of
				// the raw must start at an indexed prefix position, so no
				// match means the raw is absent from the input.
				c.values[key] = streamMatch{offset: -1}
			}
		}
	}
	return nil
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
	e.scanArchiveWith(ctx, c, budget, func(walkCtx context.Context, limits archive.Limits, visit func(archive.StreamEntry) error) error {
		return archive.WalkBytesContext(walkCtx, archiveRootName(c), c.Data, limits, visit)
	})
}

func (e *Engine) scanArchiveReader(ctx context.Context, c *sources.Chunk, input io.Reader, size int64, budget time.Duration) {
	e.scanArchiveWith(ctx, c, budget, func(walkCtx context.Context, limits archive.Limits, visit func(archive.StreamEntry) error) error {
		return archive.WalkStreamContext(walkCtx, archiveRootName(c), input, size, limits, visit)
	})
}

func (e *Engine) scanArchiveWith(ctx context.Context, c *sources.Chunk, budget time.Duration, walk func(context.Context, archive.Limits, func(archive.StreamEntry) error) error) {
	archiveCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	started := time.Now()
	timer := time.AfterFunc(budget, func() { cancel(context.DeadlineExceeded) })
	defer timer.Stop()
	err := walk(archiveCtx, archive.Limits{
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
	// Keep only small archive leaves on the historical buffered path. Larger
	// replayable leaves stay in the archive spool and use the bounded reader
	// scanner, avoiding a second body-sized allocation.
	archiveBufferedLeafThreshold = 128 << 10
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
		batch := &streamFindingBatch{}
		matchCache.pending = batch
		defer func() {
			matchCache.pending = nil
			batch.flush(ctx, e, c, matchCache)
		}()
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
	var linesBefore int
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
		if matchCache.observationActive && source == "" {
			matchCache.observeRawWindow(source, window, start)
		}
		v := decoder.Variant{Source: source, Data: window}
		base := streamWindowBase{offset: start, newlines: linesBefore, ok: source == ""}
		e.dispatchAt(ctx, c, v, archivePath, lowerPtr, true, matchCache, base)
		if start+windowSize == size {
			break
		}
		linesBefore += bytes.Count(window[:min(windowStepSize, len(window))], []byte{'\n'})
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
			e.runDetectorOnAt(ctx, c, variant, archivePath, di, data, true, matchCache, streamWindowBase{})
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
			e.emitDetectorResult(ctx, c, variant, archivePath, di, true, result, matchCache, streamWindowBase{})
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
	e.dispatchAt(ctx, c, v, archivePath, lowerPtr, false, nil, streamWindowBase{})
}

func (e *Engine) dispatchAt(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, lowerPtr *[]byte, stream bool, matchCache *streamMatchCache, base streamWindowBase) {
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
			e.runDetectorOnAt(ctx, c, v, archivePath, di, v.Data[sp.start:sp.end], stream, matchCache, base)
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
	e.runDetectorOnAt(ctx, c, v, archivePath, di, data, false, nil, streamWindowBase{})
}

func (e *Engine) runDetectorOnAt(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, data []byte, stream bool, matchCache *streamMatchCache, base streamWindowBase) {
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
		e.emitDetectorResult(ctx, c, v, archivePath, di, stream, r, matchCache, base)
	}
}

func (e *Engine) emitDetectorResult(ctx context.Context, c *sources.Chunk, v decoder.Variant, archivePath string, di int, stream bool, r detectors.Result, matchCache *streamMatchCache, base streamWindowBase) {
	d := e.dets[di]
	var hint streamRawHint
	if stream && base.ok && matchCache != nil && len(r.Raw) > 0 {
		if err := matchCache.observeRawCandidate(ctx, v.Data, base.offset, r.Raw); err != nil {
			if ctx.Err() == nil && matchCache.pending != nil && matchCache.pending.observationErr == nil {
				matchCache.pending.observationErr = err
			} else if ctx.Err() == nil {
				e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: err})
			}
		} else if matchCache.observationActive &&
			!(matchCache.pending != nil && len(r.Raw) <= streamBatchMaxRaw && matchCache.prefixListFull(r.Raw)) {
			if idx := bytes.Index(v.Data, r.Raw); idx >= 0 {
				hint = streamRawHint{
					offset:   base.offset + int64(idx),
					newlines: base.newlines + bytes.Count(v.Data[:idx], []byte{'\n'}),
					ok:       true,
				}
			}
		}
	}
	if stream {
		// Stream windows are reused for every subsequent ReadAt. Detectors are
		// allowed to return slices into their input, so findings must own their
		// secret bytes and metadata before the next window overwrites or reuses
		// those values.
		r.Raw = bytes.Clone(r.Raw)
		r.RawV2 = bytes.Clone(r.RawV2)
		r.ExtraData = maps.Clone(r.ExtraData)
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
	if stream && matchCache != nil && matchCache.pending != nil {
		if len(matchCache.pending.findings) >= streamFindingBatchLimit {
			matchCache.pending.flush(ctx, e, c, matchCache)
		}
		matchCache.pending.append(Finding{
			Result:         r,
			Chunk:          chunkForFinding(c, sourceLine(c), true),
			Detector:       d.Type(),
			VerifierBacked: e.isVerifier[di],
			rawHint:        hint,
		})
		return
	}
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
		cachedMatch, matchErr = matchCache.match(ctx, r.Raw, hint)
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

type streamRawGroup struct {
	length   int
	patterns map[string]string
}

// streamRawPrefixGroup collects the raws sharing a two-byte prefix. The
// common prefix across every member (always at least two bytes) is verified
// before any full-string map lookup, so background bytes that happen to share
// only the first byte never reach the map.
type streamRawPrefixGroup struct {
	prefix []byte
	byLen  map[int]*streamRawGroup
}

// streamRawFirstGroup splits one first-byte value into the raw group for
// single-byte raws and per-second-byte prefix groups for longer raws.
type streamRawFirstGroup struct {
	singles  *streamRawGroup
	bySecond map[byte]*streamRawPrefixGroup
}

// findReaderMatches resolves short raw values in one forward pass. The scan
// visits only offsets whose first byte is wanted, narrows candidates further
// by second byte, and confirms a group's longest common prefix before trying
// the exact string map. The overlap keeps matches crossing a block boundary
// visible without retaining the source body.
func findReaderMatches(ctx context.Context, reader io.ReaderAt, size int64, wanted map[string]struct{}, values map[string]streamMatch) error {
	if len(wanted) == 0 {
		return nil
	}
	if reader == nil || size < 0 {
		return errors.New("engine: invalid batched raw lookup input")
	}
	firsts := make(map[byte]*streamRawFirstGroup, len(wanted))
	maxLength := 0
	for raw := range wanted {
		if raw == "" {
			continue
		}
		group := firsts[raw[0]]
		if group == nil {
			group = &streamRawFirstGroup{}
			firsts[raw[0]] = group
		}
		if len(raw) == 1 {
			if group.singles == nil {
				group.singles = &streamRawGroup{length: 1, patterns: make(map[string]string)}
			}
			group.singles.patterns[raw] = raw
		} else {
			second := group.bySecond[raw[1]]
			if second == nil {
				second = &streamRawPrefixGroup{
					prefix: []byte(raw),
					byLen:  make(map[int]*streamRawGroup),
				}
				if group.bySecond == nil {
					group.bySecond = make(map[byte]*streamRawPrefixGroup)
				}
				group.bySecond[raw[1]] = second
			} else {
				second.prefix = commonPrefix(second.prefix, raw)
			}
			lengthGroup := second.byLen[len(raw)]
			if lengthGroup == nil {
				lengthGroup = &streamRawGroup{length: len(raw), patterns: make(map[string]string)}
				second.byLen[len(raw)] = lengthGroup
			}
			// Keep the caller's stable string as the map value. The compiler can
			// use the []byte slice directly for a string-key lookup, so misses do
			// not allocate; a real hit reuses this stored key.
			lengthGroup.patterns[raw] = raw
		}
		if len(raw) > maxLength {
			maxLength = len(raw)
		}
	}
	if maxLength == 0 {
		return nil
	}
	const blockSize = 64 << 10
	overlap := maxLength - 1
	buffer := make([]byte, blockSize+overlap)
	var lineCount int
	foundCount := 0
	hitCount := 0
scan:
	for start := int64(0); start < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining := size - start; remaining < want {
			want = remaining
		}
		got, err := reader.ReadAt(buffer[:int(want)], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if got != int(want) {
			return io.ErrUnexpectedEOF
		}
		data := buffer[:got]
		for first, group := range firsts {
			for from := 0; from < len(data); {
				offset := bytes.IndexByte(data[from:], first)
				if offset < 0 {
					break
				}
				offset += from
				hitCount++
				if hitCount&255 == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if singles := group.singles; singles != nil {
					key, matched := singles.patterns[string(data[offset:offset+1])]
					if matched {
						if _, alreadyFound := values[key]; !alreadyFound {
							values[key] = streamMatch{
								offset:       start + int64(offset),
								newlineCount: lineCount + bytes.Count(data[:offset], []byte{'\n'}),
								found:        true,
							}
							foundCount++
							if foundCount == len(wanted) {
								break scan
							}
						}
					}
				}
				if offset+1 >= len(data) {
					from = offset + 1
					continue
				}
				second := group.bySecond[data[offset+1]]
				if second == nil {
					from = offset + 1
					continue
				}
				prefixEnd := offset + len(second.prefix)
				if prefixEnd > len(data) || !bytes.Equal(data[offset:prefixEnd], second.prefix) {
					from = offset + 1
					continue
				}
				for _, lengthGroup := range second.byLen {
					end := offset + lengthGroup.length
					if end > len(data) {
						continue
					}
					key, matched := lengthGroup.patterns[string(data[offset:end])]
					if !matched {
						continue
					}
					if _, alreadyFound := values[key]; alreadyFound {
						continue
					}
					values[key] = streamMatch{
						offset:       start + int64(offset),
						newlineCount: lineCount + bytes.Count(data[:offset], []byte{'\n'}),
						found:        true,
					}
					foundCount++
					if foundCount == len(wanted) {
						break scan
					}
				}
				from = offset + 1
			}
		}
		if start+int64(got) == size {
			break
		}
		advance := got - overlap
		if advance <= 0 {
			return io.ErrUnexpectedEOF
		}
		lineCount += bytes.Count(data[:advance], []byte{'\n'})
		start += int64(advance)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for raw := range wanted {
		if _, ok := values[raw]; !ok {
			values[raw] = streamMatch{offset: -1}
		}
	}
	return nil
}

// commonPrefix returns the shared leading bytes of two raw strings. Members of
// a second-byte group always keep at least the two grouping bytes.
func commonPrefix(prefix []byte, raw string) []byte {
	n := min(len(prefix), len(raw))
	i := 0
	for i < n && prefix[i] == raw[i] {
		i++
	}
	return prefix[:i]
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
