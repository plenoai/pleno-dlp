package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	gogit "github.com/go-git/go-git/v5"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Newest-first in-process history stream (#1019).
//
// The sharded renderer gives every worker a contiguous slice of history, so
// N workers resolve delta chains in N distant eras at once and the shared
// delta-base cache thrashes: on django each blob version cost ~2.4 delta
// applications and 8 GB of reconstruction copies. Packs delta older
// versions against newer ones, so this path walks the whole history once,
// newest first, from a single raw `git log` and deals consecutive commits
// out to the workers in small batches. Every worker then works on the same
// era: the version an older commit needs as a base is the one a newer
// commit just read, so nearly every read is a cache hit or one delta.
// Commit order does not affect results; chunks carry their oldest-first
// ordinal for the cross-commit dedup exactly as shards do.

// nativeSynthStreamEnabled selects the stream walk for in-process
// rendering. PLENO_DLP_GIT_SYNTH_STREAM=0 keeps the sharded renderer.
func nativeSynthStreamEnabled() bool {
	return os.Getenv("PLENO_DLP_GIT_SYNTH_STREAM") != "0"
}

// nativeStreamBatchCommits and nativeStreamBatchBytes bound one dealt batch
// of raw log records: small enough that all workers stay within a narrow
// window of history, large enough that channel traffic stays negligible.
const (
	nativeStreamBatchCommits = 16
	nativeStreamBatchBytes   = 64 << 10
)

// runNativeSynthStream renders commits (oldest-first rev-list order) from
// one newest-first raw walk across workers, then resolves merges.
func (s *Source) runNativeSynthStream(ctx context.Context, repo *gogit.Repository, gitBin string, commits, merges []string, ordinals, mergeOrdinals map[string]int64, workers int, ch chan<- *sources.Chunk) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := s.nativeShardLogArgs()
	// git's tree diff is single-threaded (rails: 1.7 s for 74k commits), so
	// the raw walk is split into contiguous segments rendered in parallel;
	// the newest segment streams while older ones are buffered, keeping
	// the dealt order globally newest first.
	segs := min(max(1, len(commits)/nativeStreamSegmentCommits), nativeStreamMaxSegments)
	inputs := make([]string, segs)
	for k := range segs {
		hi := len(commits) - k*len(commits)/segs
		lo := len(commits) - (k+1)*len(commits)/segs
		var in strings.Builder
		in.Grow((hi - lo) * 41)
		for i := hi - 1; i >= lo; i-- {
			in.WriteString(commits[i])
			in.WriteByte('\n')
		}
		inputs[k] = in.String()
	}
	odb := s.objectDB(ctx, gitBin)
	// Fork every helper before the heap grows (see runNativePatchShards).
	raws := make([]*nativeLogProc, segs)
	for k := range raws {
		raws[k] = startNativeLog(ctx, gitBin, nativeRawArgs(args), inputs[k])
	}
	mergeItems := mergeWorkItems(merges, workers)
	mergeArgs := s.nativeMergeArgs()
	mergeProcs := make([]*nativeLogProc, len(mergeItems))
	res := make([]*nativeSynthRes, workers)
	resErr := make([]error, workers)
	var started sync.WaitGroup
	for i := range mergeItems {
		started.Add(1)
		go func() {
			defer started.Done()
			mergeProcs[i] = s.startItemLog(ctx, gitBin, mergeItems[i], mergeArgs)
		}()
	}
	for w := range res {
		started.Add(1)
		go func() {
			defer started.Done()
			res[w], resErr[w] = startNativeSynthRes(ctx, gitBin, s.repoAbs, odb)
		}()
	}
	started.Wait()
	defer func() {
		for _, r := range res {
			r.close()
		}
		for _, p := range mergeProcs {
			p.abandon()
		}
	}()
	abandonRaws := func() {
		for _, p := range raws {
			p.abandon()
		}
	}
	for _, p := range raws {
		if p.err != nil {
			abandonRaws()
			return p.err
		}
	}
	for _, err := range resErr {
		if err != nil {
			abandonRaws()
			return err
		}
	}

	batches := make(chan []byte, workers)
	dealErr := make(chan error, 1)
	go func() {
		defer close(batches)
		dealErr <- dealNativeRaws(ctx, raws, batches)
	}()

	errs := make([]error, workers+len(mergeItems))
	var nextMerge atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blobs := &catFileHolder{}
			defer blobs.close()
			var scan func(*sources.Chunk)
			var batch *chunkBatcher
			if s.inlineBatches != nil {
				batch = &chunkBatcher{ctx: ctx, out: s.inlineBatches}
				scan = batch.add
			}
			flush := func() {
				if batch != nil {
					batch.flush()
				}
			}
			err := s.consumeNativeStream(ctx, repo, gitBin, args, &batchReader{ctx: ctx, in: batches}, ch, scan, ordinals, blobs, res[w])
			flush()
			errs[w] = err
			if err != nil && !isCoverageOnly(err) {
				cancel()
				return
			}
			for {
				i := int(nextMerge.Add(1) - 1)
				if i >= len(mergeItems) || ctx.Err() != nil {
					return
				}
				proc := mergeProcs[i]
				mergeProcs[i] = nil
				err := s.consumeNativeMerge(ctx, repo, gitBin, proc, ch, scan, mergeOrdinals, blobs)
				flush()
				errs[workers+i] = err
				if err != nil && !isCoverageOnly(err) {
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()
	derr := <-dealErr
	var waitErr error
	var waitProc *nativeLogProc
	for _, p := range raws {
		if derr != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		if err := p.cmd.Wait(); err != nil && waitErr == nil {
			waitErr, waitProc = err, p
		}
	}
	if err := reduceShardErrors(ctx, errs); err != nil && !isCoverageOnly(err) {
		return err
	}
	if derr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("git: native raw stream: %w", derr)
	}
	if waitErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if detail := strings.TrimSpace(waitProc.stderr.String()); detail != "" {
			return fmt.Errorf("git: native raw log: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("git: native raw log: %w", waitErr)
	}
	return reduceShardErrors(ctx, errs)
}

// nativeStreamSegmentCommits and nativeStreamMaxSegments size the parallel
// raw walk segments (a variable so tests can force several segments).
var nativeStreamSegmentCommits = 8000

const nativeStreamMaxSegments = 8

// dealNativeRaws deals the segments in order: the first streams, the rest
// are read into memory concurrently so their git processes never stall.
func dealNativeRaws(ctx context.Context, raws []*nativeLogProc, out chan<- []byte) error {
	type buffered struct {
		data []byte
		err  error
	}
	rest := make([]chan buffered, len(raws))
	for k := 1; k < len(raws); k++ {
		rest[k] = make(chan buffered, 1)
		go func() {
			data, err := io.ReadAll(raws[k].stdout)
			rest[k] <- buffered{data, err}
		}()
	}
	drain := func(from int) {
		for k := from; k < len(raws); k++ {
			<-rest[k]
		}
	}
	if err := dealNativeRaw(ctx, raws[0].stdout, out); err != nil {
		_, _ = io.Copy(io.Discard, raws[0].stdout)
		for _, p := range raws[1:] {
			if p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
		}
		drain(1)
		return err
	}
	for k := 1; k < len(raws); k++ {
		b := <-rest[k]
		err := b.err
		if err == nil {
			err = dealNativeRaw(ctx, bytes.NewReader(b.data), out)
		}
		if err != nil {
			for _, p := range raws[k+1:] {
				if p.cmd.Process != nil {
					_ = p.cmd.Process.Kill()
				}
			}
			drain(k + 1)
			return err
		}
	}
	return nil
}

// dealNativeRaw splits a raw log stream into batches of whole commit
// records and sends them in stream order.
func dealNativeRaw(ctx context.Context, r io.Reader, out chan<- []byte) error {
	reader := bufio.NewReaderSize(r, 256<<10)
	var cur []byte
	commits := 0
	send := func() error {
		if len(cur) == 0 {
			return nil
		}
		select {
		case out <- cur:
		case <-ctx.Done():
			return ctx.Err()
		}
		cur, commits = nil, 0
		return nil
	}
	for {
		line, truncated, err := readNativeLine(reader, int(maxBlobSize)+1)
		if truncated {
			return fmt.Errorf("native raw line exceeds %d-byte limit", maxBlobSize)
		}
		if len(line) > 0 {
			if line[0] == nativeRecordSeparator {
				if commits >= nativeStreamBatchCommits || len(cur) >= nativeStreamBatchBytes {
					if serr := send(); serr != nil {
						return serr
					}
				}
				commits++
			}
			if cur == nil {
				cur = make([]byte, 0, nativeStreamBatchBytes+4<<10)
			}
			cur = append(cur, line...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return send()
			}
			return err
		}
	}
}

// batchReader reads the concatenation of the batches it receives; the
// stream ends when the channel closes.
type batchReader struct {
	ctx context.Context
	in  <-chan []byte
	cur []byte
}

func (b *batchReader) Read(p []byte) (int, error) {
	for len(b.cur) == 0 {
		select {
		case next, ok := <-b.in:
			if !ok {
				return 0, io.EOF
			}
			b.cur = next
		case <-b.ctx.Done():
			return 0, b.ctx.Err()
		}
	}
	n := copy(p, b.cur)
	b.cur = b.cur[n:]
	return n, nil
}

// consumeNativeStream renders the raw records read from raw in process and
// parses the result, like consumeNativeLog does for one shard.
func (s *Source) consumeNativeStream(ctx context.Context, repo *gogit.Repository, gitBin string, patchArgs []string, raw io.Reader, ch chan<- *sources.Chunk, scan func(*sources.Chunk), ordinals map[string]int64, blobs *catFileHolder, res *nativeSynthRes) error {
	// The renderer feeds the parser on this goroutine: the patch text
	// never crosses a pipe (#1033).
	parser := &nativeLogParser{
		ctx:      ctx,
		source:   s,
		repo:     repo,
		gitBin:   gitBin,
		ch:       ch,
		blobs:    blobs,
		scan:     scan,
		ordinals: ordinals,
	}
	synth := &nativeSynthLog{
		ctx:       ctx,
		source:    s,
		gitBin:    gitBin,
		patchArgs: patchArgs,
		res:       res,
		direct:    parser,
	}
	parseErr := synth.run(raw)
	if parseErr == nil {
		parseErr = parser.finish()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil && !isCoverageOnly(parseErr) {
		return parser.walkError(fmt.Errorf("git: parse native log: %w", parseErr))
	}
	return parseErr
}
