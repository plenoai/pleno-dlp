package git

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	archivepkg "github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	// offlinePatchBatchSize bounds how many verified commits are rendered by a
	// single `git log --no-walk --stdin --patch` process. The per-commit fork
	// count stays proportional to history/batchSize, not history.
	offlinePatchBatchSize = 256
	offlineSkipSampleCap  = 32
)

// repoPromisorFiltered reports whether any remote marks this clone as
// promisor (remote.<name>.promisor=true). The config is read through
// go-git's parser so section scoping, per-remote association, and boolean
// values are evaluated the way git evaluates them: a non-promisor remote's
// partialclonefilter can never justify omissions another remote made, and
// anything unreadable yields false, which fails closed — a missing object
// then degrades coverage instead of advancing a checkpoint.
func (s *Source) repoPromisorFiltered(repo *gogit.Repository) bool {
	cfg, err := repo.Config()
	if err != nil || cfg == nil || cfg.Raw == nil {
		return false
	}
	for _, remote := range cfg.Raw.Section("remote").Subsections {
		v := strings.ToLower(strings.TrimSpace(remote.Options.Get("promisor")))
		if v == "true" || v == "yes" || v == "on" || v == "1" {
			return true
		}
	}
	return false
}

type offlineRawEntry struct {
	oldSHA  string
	newSHA  string
	status  byte
	path    string
	deleted bool
	// oldMissing/newMissing record which side's blob is absent locally
	// (promisor-omitted or otherwise unavailable).
	oldMissing bool
	newMissing bool
}

// offlineCatFileCheck is one long-lived `git cat-file --batch-check` process
// used to decide which objects a filtered clone actually holds. With
// GIT_NO_LAZY_FETCH the answer is computed locally and missing promisor
// objects report as "missing" instead of triggering a network fetch.
type offlineCatFileCheck struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	// cache memoizes sizes; it is bounded so long walks stay O(cache cap),
	// not O(objects touched).
	cache map[string]int64
}

func startOfflineCatFileCheck(ctx context.Context, gitBin, repoAbs string) (*offlineCatFileCheck, error) {
	cmd := exec.CommandContext(ctx, gitBin, "-C", repoAbs, "cat-file", "--batch-check")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: cat-file batch-check stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("git: cat-file batch-check stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("git: start cat-file batch-check: %w", err)
	}
	return &offlineCatFileCheck{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64<<10),
		cache:  make(map[string]int64),
	}, nil
}

// offlineCheckCacheCap bounds the cat-file memo table so a history walk
// stays O(cap) rather than O(objects touched).
const offlineCheckCacheCap = 1 << 20

// check returns the object's size, or -1 when it is absent (promisor-omitted
// or otherwise unavailable locally). The query may be a bare object id or a
// `<rev>:<path>` object spec (used to verify merge parents' blobs).
func (c *offlineCatFileCheck) check(sha string) (int64, error) {
	if size, ok := c.cache[sha]; ok {
		return size, nil
	}
	if _, err := fmt.Fprintln(c.stdin, sha); err != nil {
		return -1, fmt.Errorf("git: cat-file batch-check write: %w", err)
	}
	line, err := c.stdout.ReadSlice('\n')
	if err != nil {
		return -1, fmt.Errorf("git: cat-file batch-check read: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) == 0 {
		return -1, fmt.Errorf("git: cat-file batch-check empty reply for %q", sha)
	}
	// Bare-id queries echo the id back; spec queries answer with the
	// resolved object id, so only validate the echo for bare ids.
	if !strings.Contains(sha, ":") && fields[0] != sha {
		return -1, fmt.Errorf("git: cat-file batch-check reply mismatch: %q", strings.TrimSpace(string(line)))
	}
	size := int64(-1)
	if len(fields) >= 3 && fields[1] != "missing" && fields[1] != "ambiguous" {
		parsed, parseErr := strconv.ParseInt(fields[2], 10, 64)
		if parseErr != nil {
			return -1, fmt.Errorf("git: cat-file batch-check size: %q", fields[2])
		}
		size = parsed
	}
	if len(c.cache) < offlineCheckCacheCap {
		c.cache[sha] = size
	}
	return size, nil
}

func (c *offlineCatFileCheck) close() {
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.cmd.Wait()
}

// offlineCatFileRead is one long-lived `git cat-file --batch` process that
// returns blob contents for locally present objects.
type offlineCatFileRead struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func startOfflineCatFileRead(ctx context.Context, gitBin, repoAbs string) (*offlineCatFileRead, error) {
	cmd := exec.CommandContext(ctx, gitBin, "-C", repoAbs, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: cat-file batch stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("git: cat-file batch stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("git: start cat-file batch: %w", err)
	}
	return &offlineCatFileRead{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 256<<10),
	}, nil
}

// stream opens a blob for reading without materializing it. The caller
// must consume (or Close, which drains) the returned stream before issuing
// the next query on this batch process. isBlob is false for missing or
// non-blob objects — their replies carry no body to drain.
func (r *offlineCatFileRead) stream(sha string) (stream io.ReadCloser, size int64, isBlob bool, err error) {
	if _, err := fmt.Fprintln(r.stdin, sha); err != nil {
		return nil, -1, false, fmt.Errorf("git: cat-file batch write: %w", err)
	}
	header, err := r.stdout.ReadSlice('\n')
	if err != nil {
		return nil, -1, false, fmt.Errorf("git: cat-file batch header: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(header)))
	if len(fields) < 3 || fields[1] != "blob" {
		return nil, -1, false, nil
	}
	size, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, -1, false, fmt.Errorf("git: cat-file batch size: %q", fields[2])
	}
	return &offlineBlobStream{r: r.stdout, remaining: size}, size, true, nil
}

// offlineBlobStream reads exactly one blob body out of a `cat-file --batch`
// stdout stream. Close drains any unread remainder plus the trailing
// record newline so the next query's reply stays aligned.
type offlineBlobStream struct {
	r         *bufio.Reader
	remaining int64
	drained   bool
}

func (s *offlineBlobStream) Read(p []byte) (int, error) {
	if s.drained {
		return 0, io.EOF
	}
	if s.remaining == 0 {
		if err := s.Close(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > s.remaining {
		p = p[:s.remaining]
	}
	n, err := s.r.Read(p)
	s.remaining -= int64(n)
	return n, err
}

func (s *offlineBlobStream) Close() error {
	if s.drained {
		return nil
	}
	s.drained = true
	var err error
	if s.remaining > 0 {
		_, err = io.CopyN(io.Discard, s.r, s.remaining)
		s.remaining = 0
	}
	if err == nil {
		// Each batch record is followed by a single newline.
		_, err = s.r.ReadByte()
	}
	return err
}

func (r *offlineCatFileRead) close() {
	_ = r.stdin.Close()
	if r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	_ = r.cmd.Wait()
}

// offlineEnum pipes the streamed commit list into one `git diff-tree
// --stdin --raw` process. Raw enumeration is tree-level only, so
// promisor-omitted blobs cannot abort it. Commits are matched to their raw
// records by hash rather than by position — diff-tree does not echo every
// commit (empty commits can produce no records) — and no per-commit
// collections are retained: only the in-flight queue and the current
// commit's own entry list live in memory, so the walk is not O(history).
type offlineEnum struct {
	commits chan nativeCommit
	raw     *bufio.Reader
	rawCmd  *exec.Cmd
	rawErr  *limitedWriter
	pumpErr chan error
	done    chan struct{}
}

// startOfflineEnum launches `git log --no-patch` and `git diff-tree --stdin
// --raw` and starts a pump that feeds each non-merge commit hash to
// diff-tree in log order while pushing the parsed commit to the consumer.
// Merge commits are collected separately — they need the combined-diff
// pass, not a raw first-parent diff.
func (s *Source) startOfflineEnum(ctx context.Context, gitBin string, starts, stops []plumbing.Hash) (*offlineEnum, error) {
	logArgs := []string{
		"-C", s.repoAbs,
		"log",
		"--no-patch",
		"--reverse",
		"--topo-order",
		"--full-history",
		"--no-show-signature",
		"--format=" + nativePrettyFormat,
	}
	if s.maxDepth > 0 {
		logArgs = append(logArgs, "--max-count="+strconv.Itoa(s.maxDepth))
	}
	if !s.since.IsZero() {
		logArgs = append(logArgs, "--since-as-filter=@"+strconv.FormatInt(s.since.Unix(), 10))
	}
	logArgs = append(logArgs, "--stdin", "--")
	logCmd := exec.CommandContext(ctx, gitBin, logArgs...)
	logCmd.Stdin = strings.NewReader(nativeRevisionInput(starts, stops))
	logStdout, err := logCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: offline commit list stdout: %w", err)
	}
	var logStderr limitedWriter
	logStderr.limit = nativeStderrLimit
	logCmd.Stderr = &logStderr
	logCmd.Env = nativeGitEnv()
	if err := logCmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start offline commit list: %w", err)
	}

	rawCmd := exec.CommandContext(ctx, gitBin,
		"-C", s.repoAbs,
		"diff-tree",
		"--stdin",
		"--always",
		"--root",
		"-r",
		"--raw",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		"--",
	)
	rawStdin, err := rawCmd.StdinPipe()
	if err != nil {
		_ = logCmd.Process.Kill()
		_ = logCmd.Wait()
		return nil, fmt.Errorf("git: offline raw stdin: %w", err)
	}
	rawStdout, err := rawCmd.StdoutPipe()
	if err != nil {
		_ = rawStdin.Close()
		_ = logCmd.Process.Kill()
		_ = logCmd.Wait()
		return nil, fmt.Errorf("git: offline raw stdout: %w", err)
	}
	var rawStderr limitedWriter
	rawStderr.limit = nativeStderrLimit
	rawCmd.Stderr = &rawStderr
	rawCmd.Env = nativeGitEnv()
	if err := rawCmd.Start(); err != nil {
		_ = rawStdin.Close()
		_ = logCmd.Process.Kill()
		_ = logCmd.Wait()
		return nil, fmt.Errorf("git: start offline raw: %w", err)
	}

	enum := &offlineEnum{
		commits: make(chan nativeCommit, 1024),
		raw:     bufio.NewReaderSize(rawStdout, 256<<10),
		rawCmd:  rawCmd,
		rawErr:  &rawStderr,
		pumpErr: make(chan error, 1),
		done:    make(chan struct{}),
	}
	go func() {
		defer close(enum.done)
		defer close(enum.commits)
		defer rawStdin.Close()
		reader := bufio.NewReaderSize(logStdout, 256<<10)
		for {
			line, err := reader.ReadSlice('\n')
			if len(line) > 0 && line[0] == nativeRecordSeparator {
				commit, parseErr := parseNativeCommit(line)
				if parseErr != nil {
					enum.pumpErr <- fmt.Errorf("git: parse offline commit list: %w", parseErr)
					return
				}
				// Feed every commit — merges included: diff-tree --always
				// echoes each ID, which is the consumer's progress signal
				// and keeps the bounded queue draining in lockstep.
				if _, err := fmt.Fprintln(rawStdin, commit.hash); err != nil {
					enum.pumpErr <- fmt.Errorf("git: feed offline raw stdin: %w", err)
					return
				}
				select {
				case enum.commits <- commit:
				case <-ctx.Done():
					enum.pumpErr <- ctx.Err()
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					enum.pumpErr <- fmt.Errorf("git: read offline commit list: %w", err)
					return
				}
				break
			}
			if err := ctx.Err(); err != nil {
				enum.pumpErr <- err
				return
			}
		}
		if err := logCmd.Wait(); err != nil {
			detail := strings.TrimSpace(logStderr.String())
			if detail != "" {
				enum.pumpErr <- fmt.Errorf("git: offline commit list: %w: %s", err, detail)
			} else {
				enum.pumpErr <- fmt.Errorf("git: offline commit list: %w", err)
			}
		}
	}()
	return enum, nil
}

// nextCommit pops queued commits until the one matching echo is found.
// Commits whose raw output produced no echo — empty commits — are passed
// through the empty callback so the caller can emit them as change-free.
func (e *offlineEnum) nextCommit(echo string, empty func(nativeCommit) error) (nativeCommit, error) {
	// The commits channel is buffered: drain it fully before declaring the
	// stream ended — a closed channel is the only reliable end marker here.
	for {
		commit, ok := <-e.commits
		if !ok {
			return nativeCommit{}, fmt.Errorf("git: offline raw echoed %q after commit stream ended", echo)
		}
		if commit.hash == echo {
			return commit, nil
		}
		if err := empty(commit); err != nil {
			return nativeCommit{}, err
		}
	}
}

// close kills the raw process; safe to call once the walk is done.
func (e *offlineEnum) close() {
	if e.rawCmd.Process != nil {
		_ = e.rawCmd.Process.Kill()
	}
	_ = e.rawCmd.Wait()
}

// offlineWalk accumulates the bounded walk state — skips, degraded
// coverage, and the lazy blob reader — shared by the commit and merge
// passes of chunksOffline.
type offlineWalk struct {
	source  *Source
	check   *offlineCatFileCheck
	blob    func() (*offlineCatFileRead, error)
	ch      chan<- *sources.Chunk
	skipped int64
	// skipSample lists the first offlineSkipSampleCap skipped entries.
	skipSample []string
	// coverage records degraded entries; coverageTotal counts them all.
	coverage      []engine.ScanFailure
	coverageTotal int
}

// chunksOffline walks a promisor-filtered clone without rendering diffs for
// objects the clone deliberately omitted. One log stream feeds one
// diff-tree --stdin stream; each commit's raw records are verified against
// a single cat-file --batch-check stream, and verified commits are rendered
// through the same `git log --patch` parser as the regular native path.
// Commits touching omitted objects emit their locally present new blobs
// whole — when the base was filtered out there is no diff to subtract, so
// the full local content is the smallest false-negative-free surface.
// Missing objects that could still be in scope degrade coverage instead of
// checkpointing; only omitted pure-deletion bases are intentional skips because
// deletions have no content to emit.
func (s *Source) chunksOffline(ctx context.Context, repo *gogit.Repository, gitBin string, starts, stops []plumbing.Hash, ch chan<- *sources.Chunk) error {
	if !s.promisorFiltered {
		// Callers coming through Chunks have this set already; populate it
		// here as well so direct invocations classify omissions correctly.
		s.promisorFiltered = s.repoPromisorFiltered(repo)
	}
	enum, err := s.startOfflineEnum(ctx, gitBin, starts, stops)
	if err != nil {
		return err
	}
	defer enum.close()
	check, err := startOfflineCatFileCheck(ctx, gitBin, s.repoAbs)
	if err != nil {
		return err
	}
	defer check.close()

	var reader *offlineCatFileRead
	blob := func() (*offlineCatFileRead, error) {
		if reader == nil {
			reader, err = startOfflineCatFileRead(ctx, gitBin, s.repoAbs)
			if err != nil {
				return nil, err
			}
		}
		return reader, nil
	}
	defer func() {
		if reader != nil {
			reader.close()
		}
	}()

	w := &offlineWalk{source: s, check: check, blob: blob, ch: ch}

	var pending []nativeCommit
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		ids := make([]string, len(pending))
		for i, commit := range pending {
			ids[i] = commit.hash
		}
		pending = nil
		return s.offlinePatchBatch(ctx, &nativeLogParser{ctx: ctx, source: s, repo: repo, gitBin: gitBin, ch: ch}, gitBin, ids)
	}
	process := func(commit nativeCommit, entries []offlineRawEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		dirty, err := w.markMissing(entries)
		if err != nil {
			return err
		}
		if !dirty {
			pending = append(pending, commit)
			if len(pending) >= offlinePatchBatchSize {
				return flush()
			}
			return nil
		}
		if err := flush(); err != nil {
			return err
		}
		return w.emitFallback(ctx, commit, entries)
	}
	// Merge commits never produce raw entries — they need the combined-diff
	// pass. Buffer them in bounded batches instead of an O(history) list.
	var mergeBuf []nativeCommit
	mergeFlush := func() error {
		if len(mergeBuf) == 0 {
			return nil
		}
		batch := mergeBuf
		mergeBuf = nil
		return w.merges(ctx, repo, gitBin, batch)
	}
	handle := func(commit nativeCommit, entries []offlineRawEntry) error {
		if commit.parentCount > 1 {
			if s.omitMergeDiffs() {
				// SkipMergeCommits/TrufflehogCompatible drop merge
				// resolution diffs on every path, partial clone or not.
				return nil
			}
			mergeBuf = append(mergeBuf, commit)
			if len(mergeBuf) >= offlinePatchBatchSize {
				return mergeFlush()
			}
			return nil
		}
		return process(commit, entries)
	}
	processEmpty := func(commit nativeCommit) error { return handle(commit, nil) }

	// Each diff-tree echo line names the commit the following raw records
	// belong to; a block is complete when the next echo arrives.
	var cur *nativeCommit
	var curEntries []offlineRawEntry
	var curPathBytes int64
	for {
		line, err := enum.raw.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return errors.New("native offline raw line exceeds buffer")
		}
		// Strip only the record terminator: paths may end in spaces.
		rec := bytes.TrimSuffix(line, []byte{'\n'})
		if len(rec) == 40 {
			if _, hexErr := hex.DecodeString(string(rec)); hexErr == nil {
				if cur != nil {
					if err := handle(*cur, curEntries); err != nil {
						return err
					}
					cur, curEntries = nil, nil
					curPathBytes = 0
				}
				commit, cerr := enum.nextCommit(string(rec), processEmpty)
				if cerr != nil {
					return cerr
				}
				cur = &commit
			}
		} else if len(rec) > 0 {
			if cur == nil || rec[0] != ':' {
				return fmt.Errorf("malformed offline raw record %q", string(rec))
			}
			entry, parseErr := parseOfflineRawEntry(rec)
			if parseErr != nil {
				return parseErr
			}
			if len(curEntries) >= nativePathLimit || curPathBytes+int64(len(entry.path)) > maxBlobSize {
				return fmt.Errorf("offline raw paths exceed %d entries or %d bytes", nativePathLimit, maxBlobSize)
			}
			curEntries = append(curEntries, entry)
			curPathBytes += int64(len(entry.path))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("git: read offline raw: %w", err)
			}
			break
		}
	}
	if cur != nil {
		if err := handle(*cur, curEntries); err != nil {
			return err
		}
	}
	// Commits diff-tree never echoed (empty commits) complete with no
	// records; drain whatever the pump already delivered.
drain:
	for {
		// Drain until the channel closes — it closes before enum.done, so
		// it is the only end marker needed and cannot lose buffered commits.
		select {
		case commit, ok := <-enum.commits:
			if !ok {
				break drain
			}
			if err := processEmpty(commit); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case err := <-enum.pumpErr:
		if err != nil {
			return err
		}
	default:
	}
	if err := enum.rawCmd.Wait(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		detail := strings.TrimSpace(enum.rawErr.String())
		if detail != "" {
			return fmt.Errorf("git: offline raw: %w: %s", err, detail)
		}
		return fmt.Errorf("git: offline raw: %w", err)
	}
	if err := flush(); err != nil {
		return err
	}

	if err := mergeFlush(); err != nil {
		return err
	}
	if w.skipped > 0 {
		fmt.Fprintf(os.Stderr, "git: %s: skipped %d promisor-omitted blob changes (intentional partial-clone boundary)\n", s.repoAbs, w.skipped)
		for _, entry := range w.skipSample {
			fmt.Fprintf(os.Stderr, "git: %s: skipped omitted blob %s\n", s.repoAbs, entry)
		}
	}
	var metadataErr error
	if s.includeCommitMetadata {
		metadataErr = s.chunksNativeMetadata(ctx, gitBin, starts, stops, ch)
	}
	return errors.Join(w.degradedErr(), metadataErr)
}

// parseOfflineRawEntry parses ":<old mode> <new mode> <old sha> <new sha>
// <status>\t<path>" records from `diff-tree --raw`. Rename/copy entries carry
// a score in the status field and two tab-separated paths; --no-renames keeps
// them out of the enumeration, but the parser accepts them for safety.
func parseOfflineRawEntry(line []byte) (offlineRawEntry, error) {
	tab := bytes.IndexByte(line, '\t')
	if tab < 0 {
		return offlineRawEntry{}, fmt.Errorf("malformed offline raw record %q", string(line))
	}
	fields := bytes.Fields(line[1:tab])
	if len(fields) != 5 {
		return offlineRawEntry{}, fmt.Errorf("malformed offline raw record %q", string(line))
	}
	oldSHA, newSHA := string(fields[2]), string(fields[3])
	for _, sha := range []string{oldSHA, newSHA} {
		if len(sha) != 40 {
			return offlineRawEntry{}, fmt.Errorf("malformed offline raw object id %q", sha)
		}
		if _, err := hex.DecodeString(sha); err != nil {
			return offlineRawEntry{}, fmt.Errorf("malformed offline raw object id %q: %w", sha, err)
		}
	}
	status := fields[4]
	if len(status) == 0 {
		return offlineRawEntry{}, fmt.Errorf("malformed offline raw record %q", string(line))
	}
	rest := bytes.Split(line[tab+1:], []byte{'\t'})
	path := rest[len(rest)-1]
	if bytes.HasPrefix(path, []byte{'"'}) {
		unquoted, err := strconv.Unquote(string(path))
		if err != nil {
			return offlineRawEntry{}, fmt.Errorf("malformed offline raw path %q: %w", string(path), err)
		}
		path = []byte(unquoted)
	}
	return offlineRawEntry{
		oldSHA:  oldSHA,
		newSHA:  newSHA,
		status:  status[0],
		path:    string(path),
		deleted: status[0] == 'D',
	}, nil
}

// markMissing verifies every blob a patch render of this commit's entries
// would touch and records which side each missing blob is on. Deleted
// entries still matter through their old blob — the render needs it even
// though deletions emit no content. Returns whether any blob is absent.
func (w *offlineWalk) markMissing(entries []offlineRawEntry) (bool, error) {
	dirty := false
	zero := strings.Repeat("0", 40)
	for i := range entries {
		entry := &entries[i]
		if entry.oldSHA != "" && entry.oldSHA != zero {
			size, err := w.check.check(entry.oldSHA)
			if err != nil {
				return false, err
			}
			if size < 0 {
				entry.oldMissing = true
				dirty = true
			}
		}
		if entry.newSHA != "" && entry.newSHA != zero {
			size, err := w.check.check(entry.newSHA)
			if err != nil {
				return false, err
			}
			if size < 0 {
				entry.newMissing = true
				dirty = true
			}
		}
	}
	return dirty, nil
}

// recordSkip counts an omitted blob that provably contributes nothing —
// currently only the base of a pure deletion on a promisor clone.
func (w *offlineWalk) recordSkip(hash, path string) {
	w.skipped++
	if len(w.skipSample) < offlineSkipSampleCap {
		w.skipSample = append(w.skipSample, fmt.Sprintf("%s:%s", hash, path))
	}
}

// recordCoverage marks a commit's coverage incomplete: a needed object is
// missing and the clone cannot prove it was out of scope.
func (w *offlineWalk) recordCoverage(commit nativeCommit, path string, err error) {
	w.coverageTotal++
	if len(w.coverage) < 32 {
		w.coverage = append(w.coverage, engine.ScanFailure{
			Kind:   engine.FailureSource,
			Source: fmt.Sprintf("%s@%s:%s", w.source.repoAbs, commit.hash, path),
			Err:    err,
		})
	}
}

// degradedErr reports the accumulated incomplete coverage.
func (w *offlineWalk) degradedErr() error {
	if w.coverageTotal == 0 {
		return nil
	}
	return &engine.DegradedError{
		Total:    w.coverageTotal,
		Counts:   map[engine.FailureKind]int{engine.FailureSource: w.coverageTotal},
		Failures: w.coverage,
	}
}

// offlinePatchBatch renders verified commits through `git log --no-walk
// --stdin --patch` — the identical diff/format flags and parser the regular
// native path uses, so chunk metadata, hunk extraction, binary detection and
// coverage semantics are byte-identical.
func (s *Source) offlinePatchBatch(ctx context.Context, parser *nativeLogParser, gitBin string, ids []string) error {
	args := []string{
		"-c", "diff.suppressBlankEmpty=false",
		"-C", s.repoAbs,
		"log",
		"--patch",
		"--root",
		"--no-walk=unsorted",
		"--no-show-signature",
		"--raw",
		"--abbrev=40",
		"--no-color",
		"--no-ext-diff",
		"--no-textconv",
		"--no-indent-heuristic",
		"--inter-hunk-context=0",
		"--ignore-submodules=all",
		"--diff-algorithm=myers",
		"--diff-merges=off",
		"--unified=3",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--format=" + nativePrettyFormat,
	}
	if s.trufflehogCompatible {
		args = append(args, "--find-renames", "--diff-filter=AM")
	} else {
		args = append(args, "--no-renames")
	}
	args = append(args, "--stdin", "--")
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git: offline patch stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git: start offline patch: %w", err)
	}
	parseErr := parser.parse(stdout)
	var coverageOnly bool
	if parseErr != nil {
		var degraded *engine.DegradedError
		coverageOnly = errors.As(parseErr, &degraded)
	}
	if parseErr != nil && !coverageOnly && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil && !coverageOnly {
		return parser.walkError(fmt.Errorf("git: parse offline patch: %w", parseErr))
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return errors.Join(parseErr, parser.walkError(fmt.Errorf("git: offline patch: %w: %s", waitErr, detail)))
		}
		return errors.Join(parseErr, parser.walkError(fmt.Errorf("git: offline patch: %w", waitErr)))
	}
	return parseErr
}

// emitFallback covers a commit whose old or new blobs were filtered out of
// the clone. Locally present new blobs are emitted whole through the normal
// text/binary policies — the same ceilings and archive/binary handling as
// emitCommit. A missing new blob on either an added path or a modification can
// hide in-scope content and therefore degrades coverage; only a missing base
// for a pure deletion is safe to skip because that change emits no content.
func (w *offlineWalk) emitFallback(ctx context.Context, commit nativeCommit, entries []offlineRawEntry) error {
	zero := strings.Repeat("0", 40)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.deleted || entry.newSHA == "" || entry.newSHA == zero {
			if entry.oldMissing && w.source.promisorFiltered {
				// Pure deletions emit nothing; an omitted base blob on a
				// promisor clone is the declared partial-clone boundary.
				w.recordSkip(commit.hash, entry.path)
			}
			continue
		}
		if !w.source.pathAllowed(entry.path) {
			continue
		}
		if entry.newMissing {
			// The blob's type cannot be sniffed without reading it, so it
			// could hold scannable text at any size: degrade coverage
			// rather than advancing a checkpoint over unread content.
			w.recordCoverage(commit, entry.path, errors.New("blob omitted by clone filter but may be in scope"))
			continue
		}
		r, err := w.blob()
		if err != nil {
			return err
		}
		if err := w.emitBlob(ctx, commit, entry.path, entry.newSHA, r); err != nil {
			return err
		}
	}
	return nil
}

// emitBlob streams one locally present blob through the same policies
// emitCommit applies to whole-file additions: binary sniffing, the binary /
// archive inclusion toggles, the artifact byte ceiling, and streaming
// emission without materializing the blob.
func (w *offlineWalk) emitBlob(ctx context.Context, commit nativeCommit, path, sha string, reader *offlineCatFileRead) error {
	stream, size, isBlob, err := reader.stream(sha)
	if err != nil {
		return err
	}
	if !isBlob {
		return nil
	}
	sniff := make([]byte, binarySniffLen)
	n, readErr := io.ReadFull(stream, sniff)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		_ = stream.Close()
		return fmt.Errorf("git: sniff blob %s: %w", sha, readErr)
	}
	body := io.MultiReader(bytes.NewReader(sniff[:n]), stream)

	parser := &nativeLogParser{ctx: ctx, source: w.source, ch: w.ch, commit: &nativeCommit{
		hash:         commit.hash,
		parentCount:  commit.parentCount,
		author:       commit.author,
		email:        commit.email,
		authoredDate: commit.authoredDate,
		message:      commit.message,
	}}
	emit := func(segment diffSegment) error {
		return parser.emitSegments(path, []diffSegment{segment})
	}

	binary := isBinary(sniff[:n])
	if binary && !w.source.includeGitArchives && !w.source.includeGitBinaries {
		return stream.Close()
	}
	if binary {
		if size > w.source.gitArtifactMaxBytes {
			_ = stream.Close()
			w.recordCoverage(commit, path, &archivepkg.PartialError{
				Kind:  "max-blob-bytes",
				Entry: path,
				Err:   fmt.Errorf("exceeds %d-byte limit", w.source.gitArtifactMaxBytes),
			})
			return nil
		}
		isArchive := w.source.includeGitArchives && archivepkg.LooksLikeArchive(sniff[:n])
		if !isArchive && !w.source.includeGitBinaries {
			return stream.Close()
		}
		return withArtifactBudget(ctx, isArchive, size, func() error {
			defer stream.Close()
			if isArchive {
				archiveCtx, cancel := context.WithTimeout(ctx, w.source.archiveTimeout)
				defer cancel()
				walkErr := archivepkg.WalkStreamContext(archiveCtx, path, body, size, w.source.archiveLimits, func(entry archivepkg.StreamEntry) error {
					return streamBlob(archiveCtx, entry.Reader, entry.Size, func(segment diffSegment) error {
						segment.path = entry.Path
						return emit(segment)
					})
				})
				if err := ctx.Err(); err != nil {
					return err
				}
				if walkErr != nil {
					w.recordCoverage(commit, path, walkErr)
				}
				return nil
			}
			spoolErr := archivepkg.WithSpoolContext(ctx, body, size, w.source.gitArtifactMaxBytes, func(validated io.Reader) error {
				return streamBlob(ctx, validated, size, emit)
			})
			if err := ctx.Err(); err != nil {
				return err
			}
			if spoolErr != nil {
				w.recordCoverage(commit, path, &archivepkg.PartialError{Kind: "corrupt-blob", Entry: path, Err: spoolErr})
			}
			return nil
		})
	}
	defer stream.Close()
	// Text policy mirrors the native path: appendFile streams text blobs
	// of any size in chunk windows, so a locally present large text blob
	// still emits — no size ceiling drops scanned text here.
	return streamBlob(ctx, body, size, emit)
}

// merges covers merge-commit resolution content the same way the regular
// native merge pass does: `diff-tree --cc` on merges whose combined diff
// blobs — result plus every parent version — are all local, whole-blob
// emission for merges whose retained result references an omitted base.
func (w *offlineWalk) merges(ctx context.Context, repo *gogit.Repository, gitBin string, merges []nativeCommit) error {
	var clean []nativeCommit
	flush := func() error {
		if len(clean) == 0 {
			return nil
		}
		ids := make([]string, len(clean))
		for i, commit := range clean {
			ids[i] = commit.hash
		}
		clean = nil
		return w.source.offlineMergePatchBatch(ctx, repo, gitBin, ids, w.ch)
	}
	visit := func(commit nativeCommit, entries []offlineRawEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := w.mergeClean(commit, entries)
		if err != nil {
			return err
		}
		if ok {
			clean = append(clean, commit)
			if len(clean) >= offlinePatchBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := flush(); err != nil {
			return err
		}
		if err := w.emitFallback(ctx, commit, entries); err != nil {
			return err
		}
		return nil
	}
	if err := w.source.offlineMergeRawBatch(ctx, gitBin, merges, visit); err != nil {
		return err
	}
	return flush()
}

// mergeClean reports whether every blob a `diff-tree --cc` render of this
// merge needs is present locally: the result blob and each parent's version
// of the path. `parent:path` object specs resolve through the tree without
// touching the blob, so a missing reply covers both "parent lacks the path"
// (harmless — the fallback just emits the result) and "blob was omitted".
func (w *offlineWalk) mergeClean(commit nativeCommit, entries []offlineRawEntry) (bool, error) {
	for i := range entries {
		entry := &entries[i]
		if entry.newSHA != "" && entry.newSHA != strings.Repeat("0", 40) {
			size, err := w.check.check(entry.newSHA)
			if err != nil {
				return false, err
			}
			if size < 0 {
				entry.newMissing = true
			}
		}
		for _, parent := range commit.parents {
			if strings.ContainsAny(entry.path, "\n\r") {
				entry.oldMissing = true
				continue
			}
			size, err := w.check.check(parent + ":" + entry.path)
			if err != nil {
				return false, err
			}
			if size < 0 {
				entry.oldMissing = true
			}
		}
	}
	for _, entry := range entries {
		if entry.oldMissing || entry.newMissing {
			return false, nil
		}
	}
	return true, nil
}

// offlineMergeRawBatch streams combined-diff entries for one bounded merge
// batch without reading a single blob. One native process keeps large merge
// histories from paying one process startup per commit, while the callback
// keeps only one commit's paths in memory.
func (s *Source) offlineMergeRawBatch(ctx context.Context, gitBin string, commits []nativeCommit, visit func(nativeCommit, []offlineRawEntry) error) error {
	if len(commits) == 0 {
		return nil
	}
	if visit == nil {
		return errors.New("git: offline merge raw callback is nil")
	}
	ids := make([]string, len(commits))
	for i, commit := range commits {
		ids[i] = commit.hash
	}
	args := []string{
		"-C", s.repoAbs,
		"diff-tree",
		"--stdin",
		"--always",
		"-c",
		"--cc",
		"-r",
		"--raw",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		"--",
	}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git: offline merge raw stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git: start offline merge raw: %w", err)
	}

	parseErr := func() error {
		reader := bufio.NewReaderSize(stdout, 256<<10)
		expected := 0
		var current *nativeCommit
		var entries []offlineRawEntry
		var pathBytes int64
		flush := func() error {
			if current == nil {
				return nil
			}
			if err := visit(*current, entries); err != nil {
				return err
			}
			current = nil
			entries = nil
			pathBytes = 0
			return nil
		}
		for {
			line, truncated, readErr := readNativeLine(reader, int(maxBlobSize)+1)
			if truncated {
				return fmt.Errorf("native offline merge raw line exceeds %d bytes", maxBlobSize)
			}
			rec := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
			if len(rec) > 0 {
				switch {
				case len(rec) == 40:
					if _, decodeErr := hex.DecodeString(string(rec)); decodeErr != nil {
						return fmt.Errorf("malformed offline merge raw commit %q", string(rec))
					}
					if err := flush(); err != nil {
						return err
					}
					if expected >= len(commits) || string(rec) != commits[expected].hash {
						return fmt.Errorf("unexpected offline merge raw commit %q at position %d", string(rec), expected)
					}
					current = &commits[expected]
					expected++
				case bytes.HasPrefix(rec, []byte("::")):
					if current == nil {
						return errors.New("offline merge raw record precedes commit echo")
					}
					entry, entryErr := parseOfflineCombinedRawEntry(string(rec))
					if entryErr != nil {
						return entryErr
					}
					if len(entries) >= nativePathLimit || pathBytes+int64(len(entry.path)) > maxBlobSize {
						return fmt.Errorf("offline merge raw paths exceed %d entries or %d bytes", nativePathLimit, maxBlobSize)
					}
					entries = append(entries, entry)
					pathBytes += int64(len(entry.path))
				default:
					return fmt.Errorf("malformed offline merge raw line %q", string(rec))
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return readErr
			}
		}
		if err := flush(); err != nil {
			return err
		}
		if expected != len(commits) {
			return fmt.Errorf("offline merge raw echoed %d of %d commits", expected, len(commits))
		}
		return nil
	}()
	if parseErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("git: offline merge raw batch: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("git: offline merge raw batch: %w", waitErr)
	}
	return nil
}

// parseOfflineCombinedRawEntry parses "::<modes...> <result sha> <status>\t<path>"
// combined-diff raw records. The result blob id is the single 40-hex field;
// the status letters are the last field before the tab.
func parseOfflineCombinedRawEntry(line string) (offlineRawEntry, error) {
	tab := strings.IndexByte(line, '\t')
	if tab < 0 {
		return offlineRawEntry{}, fmt.Errorf("malformed offline combined raw record %q", line)
	}
	fields := strings.Fields(line[2:tab])
	if len(fields) < 3 {
		return offlineRawEntry{}, fmt.Errorf("malformed offline combined raw record %q", line)
	}
	var newSHA string
	for _, field := range fields {
		if len(field) == 40 {
			if _, err := hex.DecodeString(field); err == nil {
				newSHA = field
			}
		}
	}
	if newSHA == "" {
		return offlineRawEntry{}, fmt.Errorf("malformed offline combined raw record %q", line)
	}
	status := fields[len(fields)-1]
	deleted := len(status) > 0
	for _, marker := range status {
		deleted = deleted && marker == 'D'
	}
	path := line[tab+1:]
	if strings.HasPrefix(path, "\"") {
		unquoted, err := strconv.Unquote(path)
		if err != nil {
			return offlineRawEntry{}, fmt.Errorf("malformed offline combined raw path %q: %w", path, err)
		}
		path = unquoted
	}
	return offlineRawEntry{newSHA: newSHA, status: status[0], path: path, deleted: deleted}, nil
}

// offlineMergePatchBatch renders verified merge commits through the same
// combined-diff pipeline as the regular merge pass.
func (s *Source) offlineMergePatchBatch(ctx context.Context, repo *gogit.Repository, gitBin string, ids []string, ch chan<- *sources.Chunk) error {
	args := []string{
		"-C", s.repoAbs,
		"diff-tree",
		"--stdin",
		"--root",
		"-r",
		"--raw",
		"--patch",
		"--no-show-signature",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		"--no-ext-diff",
		"--no-textconv",
		"--no-indent-heuristic",
		"--inter-hunk-context=0",
		"--ignore-submodules=all",
		"--diff-algorithm=myers",
		"--cc",
		"--unified=3",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--format=" + nativePrettyFormat,
		"--",
	}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	output, err := os.CreateTemp("", "pleno-dlp-offline-merge-*.patch")
	if err != nil {
		return fmt.Errorf("git: create offline merge spool: %w", err)
	}
	defer os.Remove(output.Name())
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stdout = output
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		_ = output.Close()
		return fmt.Errorf("git: start offline merge patch: %w", err)
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		_ = output.Close()
		return err
	}
	if waitErr != nil {
		_ = output.Close()
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("git: offline merge patch: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("git: offline merge patch: %w", waitErr)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		_ = output.Close()
		return fmt.Errorf("git: rewind offline merge spool: %w", err)
	}
	defer output.Close()
	parseErr := s.parseNativeMergeResults(ctx, repo, gitBin, output, ch)
	if parseErr != nil {
		var degraded *engine.DegradedError
		if errors.As(parseErr, &degraded) {
			return parseErr
		}
		return fmt.Errorf("git: parse offline merge patch: %w", parseErr)
	}
	return nil
}
