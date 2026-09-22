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
	"path/filepath"
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

// repoPromisorFiltered reports whether the repository at repoAbs is a partial
// (promisor) clone, i.e. some blobs referenced by its trees were deliberately
// not transferred. Such repositories cannot be walked with `git log --patch`:
// rendering a diff against an omitted object aborts the whole stream. The
// check is a plain config-file scan — go-git keeps these options under
// [remote]/[extensions] verbatim, and a filtered clone records
// promisor/partialclonefilter there.
func (s *Source) repoPromisorFiltered() bool {
	for _, path := range repoConfigPaths(s.repoAbs) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("promisor")) || bytes.Contains(lower, []byte("partialclone")) {
			return true
		}
	}
	return false
}

func repoConfigPaths(repoAbs string) []string {
	paths := []string{
		filepath.Join(repoAbs, "config"),
		filepath.Join(repoAbs, ".git", "config"),
	}
	if data, err := os.ReadFile(filepath.Join(repoAbs, ".git")); err == nil {
		if line := strings.TrimSpace(string(data)); strings.HasPrefix(line, "gitdir:") {
			gitDir := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			if !filepath.IsAbs(gitDir) {
				gitDir = filepath.Join(repoAbs, gitDir)
			}
			paths = append(paths, filepath.Join(gitDir, "config"))
			if common, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
				commonDir := strings.TrimSpace(string(common))
				if !filepath.IsAbs(commonDir) {
					commonDir = filepath.Join(gitDir, commonDir)
				}
				paths = append(paths, filepath.Join(commonDir, "config"))
			}
		}
	}
	return paths
}

// promisorOnlyOmitted reports whether an emitCommit error consists solely of
// object-not-found failures. On a promisor-filtered clone these are blobs the
// clone deliberately left out, so they are counted as intentional skips; on
// an ordinary repo the same errors still go through normal coverage
// accounting, since there the flag is never set.
func (s *Source) promisorOnlyOmitted(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		any := false
		for _, inner := range joined.Unwrap() {
			if !s.promisorOnlyOmitted(inner) {
				return false
			}
			any = true
		}
		return any
	}
	// blob:limit filters only omit blobs; a missing tree or commit is real
	// corruption and must still degrade the walk, so errors on non-blob
	// objects stay failures.
	if errors.Is(err, plumbing.ErrObjectNotFound) && !strings.Contains(err.Error(), "tree") {
		s.promisorSkipped++
		return true
	}
	return false
}

type offlineRawEntry struct {
	oldSHA  string
	newSHA  string
	status  byte
	path    string
	deleted bool
}

// offlineCatFileCheck is one long-lived `git cat-file --batch-check` process
// used to decide which objects a filtered clone actually holds. With
// GIT_NO_LAZY_FETCH the answer is computed locally and missing promisor
// objects report as "missing" instead of triggering a network fetch.
type offlineCatFileCheck struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	cache  map[string]int64
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

// check returns the object's size, or -1 when it is absent (promisor-omitted
// or otherwise unavailable locally).
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
	if len(fields) == 0 || fields[0] != sha {
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
	c.cache[sha] = size
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

func (r *offlineCatFileRead) read(sha string, maxBytes int64) (data []byte, size int64, err error) {
	if _, err := fmt.Fprintln(r.stdin, sha); err != nil {
		return nil, -1, fmt.Errorf("git: cat-file batch write: %w", err)
	}
	header, err := r.stdout.ReadSlice('\n')
	if err != nil {
		return nil, -1, fmt.Errorf("git: cat-file batch header: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(header)))
	if len(fields) < 3 || fields[1] != "blob" {
		return nil, -1, nil
	}
	size, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, -1, fmt.Errorf("git: cat-file batch size: %q", fields[2])
	}
	if size > maxBytes {
		return nil, size, nil
	}
	data = make([]byte, size+1)
	if _, err := io.ReadFull(r.stdout, data); err != nil {
		return nil, -1, fmt.Errorf("git: cat-file batch body: %w", err)
	}
	data = data[:size]
	return data, size, nil
}

func (r *offlineCatFileRead) close() {
	_ = r.stdin.Close()
	if r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	_ = r.cmd.Wait()
}

// chunksOffline walks a promisor-filtered clone without rendering diffs for
// objects the clone deliberately omitted. It enumerates commits and raw tree
// changes first (both operate on trees only, which blob:limit filters leave
// complete), verifies every touched object via one bounded cat-file
// batch-check stream, renders verified commits through the same `git log
// --patch` parser as the regular native path, and emits whole local blobs
// for commits whose old side was filtered out. Omitted blobs are counted and
// logged as intentional skips, never as a walk failure.
func (s *Source) chunksOffline(ctx context.Context, repo *gogit.Repository, gitBin string, starts, stops []plumbing.Hash, ch chan<- *sources.Chunk) error {
	commits, err := s.offlineListCommits(ctx, gitBin, starts, stops)
	if err != nil {
		return err
	}
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

	var nonMerge, merges []nativeCommit
	for _, commit := range commits {
		if commit.parentCount > 1 {
			if !s.omitMergeDiffs() {
				merges = append(merges, commit)
			}
			continue
		}
		nonMerge = append(nonMerge, commit)
	}

	rawEntries, err := s.offlineRawChanges(ctx, gitBin, nonMerge)
	if err != nil {
		return err
	}

	var skipped int64
	var skipSample []string
	var parseErrs []error

	parser := func() *nativeLogParser {
		return &nativeLogParser{ctx: ctx, source: s, repo: repo, gitBin: gitBin, ch: ch}
	}

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
		if parseErr := s.offlinePatchBatch(ctx, parser(), gitBin, ids); parseErr != nil {
			var degraded *engine.DegradedError
			if errors.As(parseErr, &degraded) {
				parseErrs = append(parseErrs, parseErr)
				return nil
			}
			return parseErr
		}
		return nil
	}

	for i, commit := range nonMerge {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries := rawEntries[i]
		clean, err := s.offlineCommitClean(check, entries)
		if err != nil {
			return err
		}
		if !clean {
			if err := flush(); err != nil {
				return err
			}
			r, err := blob()
			if err != nil {
				return err
			}
			if err := s.offlineEmitFallback(ctx, commit, entries, check, r, &skipped, &skipSample, ch); err != nil {
				return err
			}
			continue
		}
		pending = append(pending, commit)
		if len(pending) >= offlinePatchBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}

	var mergeErr error
	if len(merges) > 0 {
		mergeErr = s.offlineMerges(ctx, repo, gitBin, merges, check, blob, &skipped, &skipSample, ch)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "git: %s: skipped %d promisor-omitted blob changes (intentional partial-clone boundary)\n", s.repoAbs, skipped)
		for _, entry := range skipSample {
			fmt.Fprintf(os.Stderr, "git: %s: skipped omitted blob %s\n", s.repoAbs, entry)
		}
	}
	var metadataErr error
	if s.includeCommitMetadata {
		metadataErr = s.chunksNativeMetadata(ctx, gitBin, starts, stops, ch)
	}
	return errors.Join(errors.Join(parseErrs...), mergeErr, metadataErr)
}

// offlineListCommits replays the native revision input through
// `git log --no-patch` to get the exact commit set and ordering the patch
// walk would visit, without touching a single blob.
func (s *Source) offlineListCommits(ctx context.Context, gitBin string, starts, stops []plumbing.Hash) ([]nativeCommit, error) {
	args := []string{
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
		args = append(args, "--max-count="+strconv.Itoa(s.maxDepth))
	}
	if !s.since.IsZero() {
		args = append(args, "--since-as-filter=@"+strconv.FormatInt(s.since.Unix(), 10))
	}
	args = append(args, "--stdin", "--")
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(nativeRevisionInput(starts, stops))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: offline commit list stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start offline commit list: %w", err)
	}
	var commits []nativeCommit
	reader := bufio.NewReaderSize(stdout, 256<<10)
	var readErr error
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 && line[0] == nativeRecordSeparator {
			commit, parseErr := parseNativeCommit(line)
			if parseErr != nil {
				readErr = parseErr
				break
			}
			commits = append(commits, commit)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, fmt.Errorf("git: parse offline commit list: %w", readErr)
	}
	if err := cmd.Wait(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("git: offline commit list: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("git: offline commit list: %w", err)
	}
	return commits, nil
}

// offlineRawChanges enumerates every non-merge commit's raw tree changes in
// one `git diff-tree --stdin --raw` stream. Raw output is tree-level only, so
// promisor-omitted blobs cannot abort it.
func (s *Source) offlineRawChanges(ctx context.Context, gitBin string, commits []nativeCommit) ([][]offlineRawEntry, error) {
	out := make([][]offlineRawEntry, len(commits))
	if len(commits) == 0 {
		return out, nil
	}
	args := []string{
		"-C", s.repoAbs,
		"diff-tree",
		"--stdin",
		"--root",
		"-r",
		"--raw",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		"--",
	}
	var input strings.Builder
	for _, commit := range commits {
		fmt.Fprintln(&input, commit.hash)
	}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Stdin = strings.NewReader(input.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: offline raw stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start offline raw: %w", err)
	}
	index := -1
	reader := bufio.NewReaderSize(stdout, 256<<10)
	var readErr error
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			readErr = errors.New("native offline raw line exceeds buffer")
			break
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 40 {
			if _, hexErr := hex.DecodeString(string(trimmed)); hexErr == nil {
				index++
				if index >= len(commits) || commits[index].hash != string(trimmed) {
					readErr = fmt.Errorf("offline raw output misaligned at commit %q", string(trimmed))
					break
				}
			}
		} else if len(trimmed) > 0 {
			if index < 0 || trimmed[0] != ':' {
				readErr = fmt.Errorf("malformed offline raw record %q", string(trimmed))
				break
			}
			entry, parseErr := parseOfflineRawEntry(trimmed)
			if parseErr != nil {
				readErr = parseErr
				break
			}
			if len(out[index]) >= nativePathLimit {
				readErr = fmt.Errorf("offline raw paths exceed %d entries", nativePathLimit)
				break
			}
			out[index] = append(out[index], entry)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, fmt.Errorf("git: parse offline raw: %w", readErr)
	}
	if err := cmd.Wait(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("git: offline raw: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("git: offline raw: %w", err)
	}
	if index+1 != len(commits) {
		return nil, fmt.Errorf("git: offline raw covered %d of %d commits", index+1, len(commits))
	}
	return out, nil
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

// offlineCommitClean reports whether every blob a patch render of this commit
// would touch is present locally. Deleted entries only matter through their
// old blob, which the patch still needs for the removal diff.
func (s *Source) offlineCommitClean(check *offlineCatFileCheck, entries []offlineRawEntry) (bool, error) {
	for _, entry := range entries {
		if entry.newSHA != "" && entry.newSHA != strings.Repeat("0", 40) {
			size, err := check.check(entry.newSHA)
			if err != nil {
				return false, err
			}
			if size < 0 {
				return false, nil
			}
		}
		if entry.oldSHA != "" && entry.oldSHA != strings.Repeat("0", 40) {
			size, err := check.check(entry.oldSHA)
			if err != nil {
				return false, err
			}
			if size < 0 {
				return false, nil
			}
		}
	}
	return true, nil
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

// offlineEmitFallback covers commits whose old or new blobs were filtered
// out of the clone. Locally present new blobs are emitted whole — for a
// modification whose base was omitted there is no diff to subtract, so the
// full local content is the smallest false-negative-free surface. Omitted
// new blobs are counted as intentional skips.
func (s *Source) offlineEmitFallback(ctx context.Context, commit nativeCommit, entries []offlineRawEntry, check *offlineCatFileCheck, reader *offlineCatFileRead, skipped *int64, skipSample *[]string, ch chan<- *sources.Chunk) error {
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.deleted || entry.newSHA == "" || entry.newSHA == strings.Repeat("0", 40) {
			continue
		}
		size, err := check.check(entry.newSHA)
		if err != nil {
			return err
		}
		if size < 0 {
			s.offlineRecordSkip(skipped, skipSample, commit.hash, entry.path)
			continue
		}
		if size > s.gitArtifactMaxBytes {
			s.offlineRecordSkip(skipped, skipSample, commit.hash, entry.path)
			continue
		}
		if !s.pathAllowed(entry.path) {
			continue
		}
		data, _, err := reader.read(entry.newSHA, s.gitArtifactMaxBytes)
		if err != nil {
			return err
		}
		if data == nil {
			s.offlineRecordSkip(skipped, skipSample, commit.hash, entry.path)
			continue
		}
		if err := s.offlineEmitBlob(ctx, commit, entry.path, data, ch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) offlineRecordSkip(skipped *int64, skipSample *[]string, hash, path string) {
	*skipped++
	if len(*skipSample) < offlineSkipSampleCap {
		*skipSample = append(*skipSample, fmt.Sprintf("%s:%s", hash, path))
	}
}

func (s *Source) offlineEmitBlob(ctx context.Context, commit nativeCommit, path string, data []byte, ch chan<- *sources.Chunk) error {
	parser := &nativeLogParser{ctx: ctx, source: s, ch: ch, commit: &nativeCommit{
		hash:         commit.hash,
		parentCount:  commit.parentCount,
		author:       commit.author,
		email:        commit.email,
		authoredDate: commit.authoredDate,
		message:      commit.message,
	}}
	binary := isBinary(data)
	if binary && !s.includeGitArchives && !s.includeGitBinaries {
		return nil
	}
	if binary {
		isArchive := s.includeGitArchives && archivepkg.LooksLikeArchive(data[:min(len(data), binarySniffLen)])
		if !isArchive && !s.includeGitBinaries {
			return nil
		}
		size := int64(len(data))
		return withArtifactBudget(ctx, isArchive, size, func() error {
			if isArchive {
				archiveCtx, cancel := context.WithTimeout(ctx, s.archiveTimeout)
				defer cancel()
				return archivepkg.WalkStreamContext(archiveCtx, path, bytes.NewReader(data), size, s.archiveLimits, func(entry archivepkg.StreamEntry) error {
					return streamBlob(archiveCtx, entry.Reader, entry.Size, func(segment diffSegment) error {
						return parser.emitSegments(entry.Path, []diffSegment{segment})
					})
				})
			}
			return parser.emitSegments(path, splitBlob(data))
		})
	}
	return parser.emitSegments(path, splitBlob(data))
}

// offlineMerges covers merge-commit resolution content the same way the
// regular native merge pass does: `diff-tree --cc` on merges whose combined
// result blobs are all local, whole-blob emission for merges that reference
// omitted blobs.
func (s *Source) offlineMerges(ctx context.Context, repo *gogit.Repository, gitBin string, merges []nativeCommit, check *offlineCatFileCheck, blob func() (*offlineCatFileRead, error), skipped *int64, skipSample *[]string, ch chan<- *sources.Chunk) error {
	var clean []nativeCommit
	var parseErrs []error
	flush := func() error {
		if len(clean) == 0 {
			return nil
		}
		ids := make([]string, len(clean))
		for i, commit := range clean {
			ids[i] = commit.hash
		}
		clean = nil
		if err := s.offlineMergePatchBatch(ctx, repo, gitBin, ids, ch); err != nil {
			var degraded *engine.DegradedError
			if errors.As(err, &degraded) {
				parseErrs = append(parseErrs, err)
				return nil
			}
			return err
		}
		return nil
	}
	for _, commit := range merges {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := s.offlineMergeRaw(ctx, gitBin, commit)
		if err != nil {
			return err
		}
		ok, err := s.offlineCommitClean(check, entries)
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
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		r, err := blob()
		if err != nil {
			return err
		}
		if err := s.offlineEmitFallback(ctx, commit, entries, check, r, skipped, skipSample, ch); err != nil {
			return err
		}
	}
	if err := flush(); err != nil {
		return err
	}
	return errors.Join(parseErrs...)
}

// offlineMergeRaw lists a merge's combined-diff entries — files whose merged
// result differs from every parent — without reading a single blob.
func (s *Source) offlineMergeRaw(ctx context.Context, gitBin string, commit nativeCommit) ([]offlineRawEntry, error) {
	args := []string{
		"-C", s.repoAbs,
		"diff-tree",
		"-c",
		"--cc",
		"-r",
		"--raw",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		commit.hash,
		"--",
	}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("git: offline merge raw %s: %w: %s", commit.hash, err, detail)
		}
		return nil, fmt.Errorf("git: offline merge raw %s: %w", commit.hash, err)
	}
	var entries []offlineRawEntry
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "::") {
			continue
		}
		entry, err := parseOfflineCombinedRawEntry(trimmed)
		if err != nil {
			return nil, err
		}
		if len(entries) >= nativePathLimit {
			return nil, fmt.Errorf("offline merge raw paths exceed %d entries", nativePathLimit)
		}
		entries = append(entries, entry)
	}
	return entries, nil
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
