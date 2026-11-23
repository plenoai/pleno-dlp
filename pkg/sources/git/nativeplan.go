package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// nativeCostPlanMaxCommits bounds the histories that get a cost-based work
// plan. The plan needs one extra tree-diff pass (about 15 µs per commit), and
// skew only bounds wall time when the heaviest commit is large relative to an
// equal share of the history: in long histories each batch already carries
// thousands of commits, so contiguous batches stay balanced.
var nativeCostPlanMaxCommits = 20000

// nativeCostPlanItemsPerWorker sets how many work items the cost plan aims
// for per worker. More items would absorb estimation error, but every item
// is one more git process, and spawning costs about 1 ms of serialized fork
// plus copy-on-write faults in the scanner (croc: 4 items per worker took
// 0.41 s against 0.37 s for one).
const nativeCostPlanItemsPerWorker = 1

// nativeWorkItem is one `git log` invocation of a shard plan: the commits to
// render and, when a single heavy commit is split, the subset of its paths.
type nativeWorkItem struct {
	commits []string
	paths   []string
	cost    int
	// merge renders commits' dense combined merge patches (diff-tree --cc)
	// instead of their ordinary history.
	merge bool
}

// nativeMergeBatchMin is the smallest number of merges one merge item
// renders, so small merge sets do not cost a process per worker.
const nativeMergeBatchMin = 500

// mergeWorkItems splits the merges into at most shards contiguous items.
func mergeWorkItems(merges []string, shards int) []nativeWorkItem {
	if len(merges) == 0 {
		return nil
	}
	parts := (len(merges) + nativeMergeBatchMin - 1) / nativeMergeBatchMin
	if parts > shards {
		parts = shards
	}
	size := (len(merges) + parts - 1) / parts
	var items []nativeWorkItem
	for lo := 0; lo < len(merges); lo += size {
		items = append(items, nativeWorkItem{commits: merges[lo:min(lo+size, len(merges))], merge: true})
	}
	return items
}

// stdin renders the item as `git log --stdin` input. Paths follow a "--"
// separator, which git reads as pathspecs; the caller runs git with
// --literal-pathspecs so they never act as globs or magic.
func (it nativeWorkItem) stdin() string {
	var b strings.Builder
	for _, c := range it.commits {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	if len(it.paths) > 0 {
		b.WriteString("--\n")
		for _, p := range it.paths {
			b.WriteString(p)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// contiguousWorkItems is the cost-blind plan: equal contiguous batches.
func contiguousWorkItems(commits []string, shards int) []nativeWorkItem {
	parts := shards * nativeShardBatchesPerWorker
	batchSize := (len(commits) + parts - 1) / parts
	if batchSize < nativeShardMinBatch {
		batchSize = nativeShardMinBatch
	}
	var items []nativeWorkItem
	for lo := 0; lo < len(commits); lo += batchSize {
		items = append(items, nativeWorkItem{commits: commits[lo:min(lo+batchSize, len(commits))]})
	}
	return items
}

// nativeWorkPlan splits the selected commits into work items. Short histories
// whose cost is dominated by a few huge commits (a vendor import) get a
// cost-based plan in which every commit costs one plus its changed files and
// a commit heavier than one item's share is split by path across items (#985).
// Any failure of the cost pass falls back to contiguous batches: the plan
// changes only scheduling, never which (commit, path) patches are rendered.
//
// cost delivers the cost pass result started by startNativeCostPass; nil
// means no cost pass ran.
func (s *Source) nativeWorkPlan(commits []string, shards int, cost <-chan nativeCostResult) []nativeWorkItem {
	if cost == nil || len(commits) > nativeCostPlanMaxCommits {
		return contiguousWorkItems(commits, shards)
	}
	res := <-cost
	files, err := res.files, res.err
	if err != nil {
		return contiguousWorkItems(commits, shards)
	}
	return costWorkItems(commits, files, shards*nativeCostPlanItemsPerWorker)
}

// costWorkItems packs commits, in order, into about parts items of equal
// cost and splits any commit costlier than one item by path. Items are
// returned heaviest first so the longest renders start earliest.
func costWorkItems(commits []string, files map[string][]string, parts int) []nativeWorkItem {
	total := 0
	for _, c := range commits {
		total += 1 + len(files[c])
	}
	target := (total + parts - 1) / parts
	if target < 1 {
		target = 1
	}
	var items []nativeWorkItem
	var cur nativeWorkItem
	flush := func() {
		if len(cur.commits) > 0 {
			items = append(items, cur)
		}
		cur = nativeWorkItem{}
	}
	for _, c := range commits {
		paths := files[c]
		cost := 1 + len(paths)
		if cost > target && splittablePaths(paths) {
			for lo := 0; lo < len(paths); lo += target {
				part := paths[lo:min(lo+target, len(paths))]
				items = append(items, nativeWorkItem{commits: []string{c}, paths: part, cost: len(part)})
			}
			continue
		}
		if cur.cost > 0 && cur.cost+cost > target {
			flush()
		}
		cur.commits = append(cur.commits, c)
		cur.cost += cost
	}
	flush()
	sort.SliceStable(items, func(i, j int) bool { return items[i].cost > items[j].cost })
	return items
}

// splittablePaths reports whether paths can be passed one per line as
// literal pathspecs and stays within the parser's per-commit raw limit,
// whose overflow error a split render would otherwise hide.
func splittablePaths(paths []string) bool {
	if len(paths) < 2 || len(paths) >= nativePathLimit {
		return false
	}
	for _, p := range paths {
		if p == "" || strings.ContainsAny(p, "\n\r") {
			return false
		}
	}
	return true
}

type nativeCostResult struct {
	files map[string][]string
	err   error
}

// startNativeCostPass starts the cost pass over the same revision input as
// the rev-list, concurrently with it, so short histories do not pay for it
// serially. It walks a superset of the selection (no depth or date filter);
// extra commits are ignored. The caller cancels it via ctx when the history
// turns out too long for a cost plan. Trufflehog mode returns nil: it
// detects renames, which a path-limited render would turn into additions.
func (s *Source) startNativeCostPass(ctx context.Context, gitBin, revisions string) <-chan nativeCostResult {
	if s.trufflehogCompatible {
		return nil
	}
	out := make(chan nativeCostResult, 1)
	go func() {
		files, err := s.nativeChangedPaths(ctx, gitBin, revisions)
		out <- nativeCostResult{files, err}
	}()
	return out
}

// nativeChangedPaths lists, per commit reachable from revisions, the
// non-deleted paths the shard render will diff (the same filters as
// nativeShardLogArgs, without patches). Duplicate paths (a type change) are
// kept once.
func (s *Source) nativeChangedPaths(ctx context.Context, gitBin, revisions string) (map[string][]string, error) {
	args := []string{"-C", s.repoAbs, "log", "--root", "--full-history", "--stdin", "--raw", "-r", "-z",
		"--no-renames", "--diff-filter=d", "--diff-merges=off", "--ignore-submodules=all",
		"--no-abbrev", "--no-show-signature", "--format=%x01%H", "--"}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(revisions)
	cmd.Env = nativeGitEnv()
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git: native cost pass: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseChangedPaths(out)
}

// parseChangedPaths parses `git log --raw -z --format=%x01%H` output.
func parseChangedPaths(out []byte) (map[string][]string, error) {
	files := make(map[string][]string)
	var commit string
	var last string
	fields := bytes.Split(out, []byte{0})
	for i := 0; i < len(fields); i++ {
		f := bytes.TrimLeft(fields[i], "\n")
		switch {
		case len(f) == 0:
		case f[0] == 0x01:
			commit = string(bytes.TrimSpace(f[1:]))
			if len(commit) != 40 {
				return nil, fmt.Errorf("git: native cost pass: malformed commit %q", commit)
			}
			last = ""
		case f[0] == ':':
			if commit == "" || i+1 >= len(fields) {
				return nil, fmt.Errorf("git: native cost pass: raw record outside a commit")
			}
			i++
			p := string(fields[i])
			if p != last {
				files[commit] = append(files[commit], p)
				last = p
			}
		default:
			return nil, fmt.Errorf("git: native cost pass: unexpected field %q", f)
		}
	}
	return files, nil
}
