package git

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// nativeShardMinCommits is the smallest number of commits each parallel
// `git log` shard receives. Below it the fork and rev-list overhead outweighs
// the parallel diff generation, so small histories keep the single stream.
var nativeShardMinCommits = 100

// nativeShardBatchesPerWorker and nativeShardMinBatch size the work queue:
// enough batches per worker to even out skewed commits, but never so small
// that per-process startup dominates.
const (
	nativeShardBatchesPerWorker = 1
	nativeShardMinBatch         = 50
)

// lockedWriter serializes whole Write calls from concurrent shard parsers
// onto the merge pass stdin; each parser writes one complete line per call.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// runNativePatchLog renders and parses the patch history for the selected
// revisions. Patch rendering (`git log -p`) is single-threaded inside git and
// dominated full-history wall time (rails: 22 s of 25 s), so large histories
// are split into contiguous commit ranges rendered by parallel
// `git log --no-walk=unsorted` processes. Every selected commit is rendered
// exactly once either way; only the interleaving of chunks across shards
// differs. The history result is nil, a coverage-only *engine.DegradedError,
// or a fatal error; mergeErr reports a merge-resolution failure (wantMerges)
// when the history result is not fatal.
func (s *Source) runNativePatchLog(ctx context.Context, repo *gogit.Repository, gitBin string, starts, stops []plumbing.Hash, wantMerges bool, ch chan<- *sources.Chunk) (historyErr, mergeErr error) {
	shards := s.nativeShardCount()
	if shards > 1 {
		costCtx, cancelCost := context.WithCancel(ctx)
		defer cancelCost()
		cost := s.startNativeCostPass(costCtx, gitBin, nativeRevisionInput(starts, stops))
		commits, merges, err := s.nativeSelectedCommits(ctx, gitBin, starts, stops)
		if err != nil {
			return err, nil
		}
		if len(commits) > nativeCostPlanMaxCommits {
			cancelCost()
		}
		if n := len(commits) / nativeShardMinCommits; n < shards {
			shards = n
		}
		if shards > 1 {
			if !wantMerges {
				merges = nil
			}
			return s.runNativePatchShards(ctx, repo, gitBin, commits, merges, shards, cost, ch), nil
		}
	}
	return s.runNativeSingleStream(ctx, repo, gitBin, starts, stops, wantMerges, ch)
}

func (s *Source) nativeShardCount() int {
	n := s.concurrency
	// Each shard is a git process plus a parser goroutine, and the engine
	// runs its own concurrency-sized worker pool on the same cores. Capping
	// shards at three quarters of the CPUs leaves room for the detectors
	// instead of oversubscribing (#995).
	if cpus := max(1, runtime.NumCPU()*3/4); n > cpus {
		n = cpus
	}
	return n
}

// nativeSelectedCommits lists the commits nativeLogArgs would render, in the
// same reverse topological order and with the same depth and date filters,
// and reports which of them are merges.
func (s *Source) nativeSelectedCommits(ctx context.Context, gitBin string, starts, stops []plumbing.Hash) ([]string, []string, error) {
	args := []string{"-C", s.repoAbs, "rev-list", "--parents", "--reverse", "--topo-order", "--full-history"}
	if s.maxDepth > 0 {
		args = append(args, "--max-count="+strconv.Itoa(s.maxDepth))
	}
	if !s.since.IsZero() {
		args = append(args, "--since-as-filter=@"+strconv.FormatInt(s.since.Unix(), 10))
	}
	args = append(args, "--stdin", "--")
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(nativeRevisionInput(starts, stops))
	cmd.Env = nativeGitEnv()
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, fmt.Errorf("git: native rev-list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var commits, merges []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields {
			if len(f) != 40 {
				return nil, nil, fmt.Errorf("git: native rev-list: malformed commit line %q", line)
			}
		}
		commits = append(commits, fields[0])
		if len(fields) > 2 {
			merges = append(merges, fields[0])
		}
	}
	return commits, merges, nil
}

// nativeShardLogArgs renders exactly the commits given on stdin, in input
// order, with the same patch options as nativeLogArgs.
func (s *Source) nativeShardLogArgs() []string {
	base := s.nativeLogArgs()
	args := make([]string, 0, len(base)+1)
	for _, arg := range base {
		switch {
		case arg == "--reverse", arg == "--topo-order", arg == "--full-history",
			strings.HasPrefix(arg, "--max-count="), strings.HasPrefix(arg, "--since-as-filter="):
			continue
		case arg == "--stdin":
			args = append(args, "--no-walk=unsorted")
			if !s.trufflehogCompatible {
				// Deleted files contribute only removed lines, which are
				// never scanned; skip rendering them (croc's vendor
				// removal alone is ~100 MB of "-" lines). Trufflehog mode
				// already restricts to --diff-filter=AM.
				args = append(args, "--diff-filter=d")
			}
		}
		args = append(args, arg)
	}
	return args
}

func (s *Source) runNativePatchShards(ctx context.Context, repo *gogit.Repository, gitBin string, commits, merges []string, shards int, cost <-chan nativeCostResult, ch chan<- *sources.Chunk) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := s.nativeShardLogArgs()
	// Shards finish out of order, so every chunk carries its commit's
	// oldest-first position for the cross-commit dedup to pick the
	// introducing commit.
	ordinals := make(map[string]int64, len(commits))
	for i, c := range commits {
		ordinals[c] = int64(i + 1)
	}
	// Merge resolutions used to arrive after all ordinary history from one
	// spooled diff-tree pass, so they lost every cross-commit tie on arrival
	// order and ranked among themselves in rev-list order. They now render
	// as parallel work items (#978); ordinals past the ordinary history keep
	// exactly that ranking.
	mergeOrdinals := make(map[string]int64, len(merges))
	for i, m := range merges {
		mergeOrdinals[m] = int64(len(commits) + 1 + i)
	}
	// Commit cost is highly skewed (an import commit can dwarf thousands of
	// one-line fixes), so equal contiguous ranges leave most workers idle
	// behind one heavy shard. Workers instead pull work items from a shared
	// queue; short histories get a cost-based plan that also splits a heavy
	// commit by path (#985).
	batches := append(s.nativeWorkPlan(commits, shards, cost), mergeWorkItems(merges, shards)...)
	pathArgs := append([]string{"--literal-pathspecs"}, args...)
	mergeArgs := s.nativeMergeArgs()
	itemArgs := func(it nativeWorkItem) []string {
		switch {
		case it.merge:
			return mergeArgs
		case len(it.paths) > 0:
			return pathArgs
		}
		return args
	}
	// Start every item's git process before any chunk is scanned. Go forks
	// child processes on darwin, and each fork write-protects the parent's
	// heap, so a fork in the middle of the scan makes every scan worker
	// re-fault the pages it writes next (croc: 9 s of system time with one
	// fork per item). One burst while the heap is small pays that once.
	procs := make([]*nativeLogProc, len(batches))
	var startNext atomic.Int64
	var started sync.WaitGroup
	for w := 0; w < shards; w++ {
		started.Add(1)
		go func() {
			defer started.Done()
			for {
				i := int(startNext.Add(1) - 1)
				if i >= len(batches) || i >= nativeEagerStartMax {
					return
				}
				procs[i] = s.startItemLog(ctx, gitBin, batches[i], itemArgs(batches[i]))
			}
		}()
	}
	// Each worker's renderer helpers start in the same burst (see above).
	synthRes := make([]*nativeSynthRes, shards)
	if s.nativeSynthEligible() {
		for w := range synthRes {
			started.Add(1)
			go func() {
				defer started.Done()
				synthRes[w], _ = startNativeSynthRes(ctx, gitBin, s.repoAbs)
			}()
		}
	}
	started.Wait()
	defer func() {
		for _, r := range synthRes {
			r.close()
		}
	}()
	defer func() {
		for _, p := range procs {
			p.abandon()
		}
	}()
	errs := make([]error, len(batches))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < shards; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := synthRes[w]
			// One cat-file batch per worker serves all of its items, so
			// binary classification does not fork per item.
			blobs := &catFileHolder{}
			defer blobs.close()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(batches) || ctx.Err() != nil {
					return
				}
				proc := procs[i]
				if proc == nil {
					proc = s.startItemLog(ctx, gitBin, batches[i], itemArgs(batches[i]))
				}
				procs[i] = nil
				var scan func(*sources.Chunk)
				var batch *chunkBatcher
				if s.inlineBatches != nil {
					batch = &chunkBatcher{ctx: ctx, out: s.inlineBatches}
					scan = batch.add
				}
				var err error
				if batches[i].merge {
					err = s.consumeNativeMerge(ctx, repo, gitBin, proc, ch, scan, mergeOrdinals, blobs)
				} else {
					err = s.consumeNativeLog(ctx, repo, gitBin, proc, nil, ch, scan, ordinals, blobs, res)
				}
				if batch != nil {
					batch.flush()
				}
				errs[i] = err
				if err != nil && !isCoverageOnly(err) {
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		// Either the caller cancelled or a batch failed; a failed batch
		// is reported below in preference to the cancellations it caused.
		failed := false
		for _, e := range errs {
			if e != nil && !isCoverageOnly(e) && !errors.Is(e, context.Canceled) {
				failed = true
			}
		}
		if !failed {
			return err
		}
	}

	merged := &engine.DegradedError{Counts: map[engine.FailureKind]int{}}
	var fatal []error
	for _, err := range errs {
		if err == nil {
			continue
		}
		if coverage, ok := err.(*engine.DegradedError); ok {
			merged.Total += coverage.Total
			for kind, n := range coverage.Counts {
				merged.Counts[kind] += n
			}
			merged.Failures = append(merged.Failures, coverage.Failures...)
			continue
		}
		if errors.Is(err, context.Canceled) && ctx.Err() != nil && len(fatal) > 0 {
			continue
		}
		fatal = append(fatal, err)
	}
	if len(fatal) > 0 {
		// Prefer a real failure over the cancellations it caused in
		// sibling shards.
		for _, err := range fatal {
			if !errors.Is(err, context.Canceled) {
				return err
			}
		}
		return fatal[0]
	}
	if merged.Total == 0 {
		return nil
	}
	return merged
}

// nativeEagerStartMax bounds how many shard processes start up front; the
// rest start when a worker reaches them.
const nativeEagerStartMax = 256

// nativeLogProc is a started native `git log` whose output is not yet read.
type nativeLogProc struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr *limitedWriter
	err    error
	// synth marks a raw-only `git log` whose patches the in-process
	// renderer produces (#983); patchArgs and pathspec describe the
	// equivalent patch invocation for per-commit git fallbacks.
	synth     bool
	patchArgs []string
	pathspec  string
}

// startPatchLog starts the history rendering for patch-mode log args: a
// raw-only walk rendered in process when eligible, else `git log -p`.
func (s *Source) startPatchLog(ctx context.Context, gitBin string, args []string, stdin string) *nativeLogProc {
	if !s.nativeSynthEligible() {
		return startNativeLog(ctx, gitBin, args, stdin)
	}
	p := startNativeLog(ctx, gitBin, nativeRawArgs(args), stdin)
	p.synth = true
	p.patchArgs = args
	if i := strings.Index(stdin, "--\n"); i >= 0 && (i == 0 || stdin[i-1] == '\n') {
		p.pathspec = stdin[i:]
	}
	return p
}

func startNativeLog(ctx context.Context, gitBin string, args []string, stdin string) *nativeLogProc {
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	p := &nativeLogProc{cmd: cmd, stderr: &limitedWriter{limit: nativeStderrLimit}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		p.err = fmt.Errorf("git: native log stdout: %w", err)
		return p
	}
	p.stdout = stdout
	cmd.Stderr = p.stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		p.err = fmt.Errorf("git: start native log: %w", err)
	}
	return p
}

// startItemLog starts one work item: merges keep git's combined-diff
// rendering, ordinary history goes through startPatchLog.
func (s *Source) startItemLog(ctx context.Context, gitBin string, it nativeWorkItem, args []string) *nativeLogProc {
	if it.merge {
		return startNativeLog(ctx, gitBin, args, it.stdin())
	}
	return s.startPatchLog(ctx, gitBin, args, it.stdin())
}

// abandon kills and reaps a process no worker consumed. Nil-safe.
func (p *nativeLogProc) abandon() {
	if p == nil || p.err != nil {
		return
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
}

// runNativeLogProcess runs one native `git log` and streams it through a
// fresh parser.
func (s *Source) runNativeLogProcess(ctx context.Context, repo *gogit.Repository, gitBin string, args []string, stdin string, mergeInput io.Writer, ch chan<- *sources.Chunk, scan func(*sources.Chunk), ordinals map[string]int64) error {
	blobs := &catFileHolder{}
	defer blobs.close()
	return s.consumeNativeLog(ctx, repo, gitBin, s.startPatchLog(ctx, gitBin, args, stdin), mergeInput, ch, scan, ordinals, blobs, nil)
}

// consumeNativeLog parses a started native `git log` and waits for it. blobs
// is the caller's cat-file holder for binary classification; res, when
// non-nil, are the caller's renderer helpers for a synth proc.
func (s *Source) consumeNativeLog(ctx context.Context, repo *gogit.Repository, gitBin string, proc *nativeLogProc, mergeInput io.Writer, ch chan<- *sources.Chunk, scan func(*sources.Chunk), ordinals map[string]int64, blobs *catFileHolder, res *nativeSynthRes) error {
	if proc.err != nil {
		return proc.err
	}
	cmd, stderr := proc.cmd, proc.stderr
	var stdout io.Reader = proc.stdout
	var render *nativeRender
	if proc.synth {
		var err error
		render, err = s.startNativeRender(ctx, gitBin, proc, res)
		if err != nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
			return err
		}
		stdout = render.out
	}
	parser := nativeLogParser{
		ctx:        ctx,
		source:     s,
		repo:       repo,
		gitBin:     gitBin,
		ch:         ch,
		mergeInput: mergeInput,
		blobs:      blobs,
		scan:       scan,
		ordinals:   ordinals,
	}
	if ordinals == nil {
		parser.seq = new(int64)
	}
	parseErr := parser.parse(stdout)
	var parseCoverage *engine.DegradedError
	parseOnlyCoverage := errors.As(parseErr, &parseCoverage)
	if parseErr != nil && !parseOnlyCoverage && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if render != nil {
		render.stop()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil && !parseOnlyCoverage {
		return parser.walkError(fmt.Errorf("git: parse native log: %w", parseErr))
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return errors.Join(parseErr, parser.walkError(fmt.Errorf("git: native log: %w: %s", waitErr, detail)))
		}
		return errors.Join(parseErr, parser.walkError(fmt.Errorf("git: native log: %w", waitErr)))
	}
	return parseErr
}

// consumeNativeMerge parses a started merge diff-tree item and waits for it.
func (s *Source) consumeNativeMerge(ctx context.Context, repo *gogit.Repository, gitBin string, proc *nativeLogProc, ch chan<- *sources.Chunk, scan func(*sources.Chunk), ordinals map[string]int64, blobs *catFileHolder) error {
	if proc.err != nil {
		return proc.err
	}
	parseErr := s.parseNativeMergeResults(ctx, repo, gitBin, proc.stdout, ch, scan, ordinals, blobs)
	if parseErr != nil && !isCoverageOnly(parseErr) && proc.cmd.Process != nil {
		_ = proc.cmd.Process.Kill()
	}
	waitErr := proc.cmd.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil && !isCoverageOnly(parseErr) {
		return fmt.Errorf("git: parse native merge patch: %w", parseErr)
	}
	if waitErr != nil {
		if detail := strings.TrimSpace(proc.stderr.String()); detail != "" {
			return fmt.Errorf("git: native merge raw: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("git: native merge raw: %w", waitErr)
	}
	return parseErr
}

// isCoverageOnly reports whether err is exactly a parser coverage report
// (localized, non-fatal) rather than a fatal error that may wrap one.
func isCoverageOnly(err error) bool {
	_, ok := err.(*engine.DegradedError)
	return ok
}

// ChunksInline implements sources.InlineScanner. Parallel history shards
// hand chunks to a private pool of workers in batches of nativeInlineBatch,
// so ~500k small diff chunks cost ~8k channel operations instead of 500k
// contended ones on the engine's shared channel, while chunks of one heavy
// shard still spread across every worker. Everything else (single-stream
// walks, merge resolutions, commit metadata, artifacts) still goes through ch.
func (s *Source) ChunksInline(ctx context.Context, ch chan<- *sources.Chunk, workers int, scan func(*sources.Chunk)) error {
	if workers < 1 {
		workers = 1
	}
	batches := make(chan []*sources.Chunk, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batches {
				for _, c := range batch {
					scan(c)
				}
			}
		}()
	}
	s.inlineBatches = batches
	err := s.Chunks(ctx, ch)
	s.inlineBatches = nil
	close(batches)
	wg.Wait()
	return err
}

// nativeInlineBatch bounds how many chunks (and bytes) a shard parser
// accumulates before handing them to the inline worker pool.
const (
	nativeInlineBatch      = 64
	nativeInlineBatchBytes = 1 << 20
)

// chunkBatcher accumulates one shard parser's chunks. Not safe for
// concurrent use; each shard run owns one.
type chunkBatcher struct {
	ctx     context.Context
	out     chan<- []*sources.Chunk
	pending []*sources.Chunk
	bytes   int
}

func (b *chunkBatcher) add(c *sources.Chunk) {
	b.pending = append(b.pending, c)
	b.bytes += len(c.Data)
	if len(b.pending) >= nativeInlineBatch || b.bytes >= nativeInlineBatchBytes {
		b.flush()
	}
}

func (b *chunkBatcher) flush() {
	if len(b.pending) == 0 {
		return
	}
	select {
	case b.out <- b.pending:
	case <-b.ctx.Done():
	}
	b.pending, b.bytes = nil, 0
}
