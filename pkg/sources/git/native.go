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
	"sync"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	nativeRecordSeparator = byte(0x1e)
	nativeFieldSeparator  = byte(0x00)
	nativeStderrLimit     = 64 << 10
	nativePathLimit       = 64 << 10
	nativeSegmentLimit    = 64 << 10
	nativePrettyFormat    = "%x1e%H%x00%P%x00%an%x00%ae%x00%aI%x00%s%x00"
)

var nativeCapabilityCache sync.Map

func (s *Source) nativeFastPathEligible(startCount int) bool {
	return !s.includeCommitMetadata && !s.includeGitArchives && !s.includeGitBinaries &&
		(s.maxDepth == 0 || startCount == 1)
}

// nativeFastPathSupported probes required git-log flags before any chunk can
// be emitted. The result is binary-specific and cached process-wide so an org
// scan pays for one short subprocess, not one per repository.
func (s *Source) nativeFastPathSupported(ctx context.Context, gitBin string, start plumbing.Hash) (bool, error) {
	if cached, ok := nativeCapabilityCache.Load(gitBin); ok {
		return cached.(bool), nil
	}
	args := []string{
		"-c", "diff.suppressBlankEmpty=false",
		"-C", s.repoAbs,
		"log",
		"--max-count=0",
		"--patch",
		"--root",
		"--no-show-signature",
		"--no-ext-diff",
		"--no-textconv",
		"--no-indent-heuristic",
		"--inter-hunk-context=0",
		"--ignore-submodules=all",
		"--diff-merges=off",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--since-as-filter=@0",
		"--format=" + nativePrettyFormat,
		start.String(),
		"--",
	}
	cmd := exec.CommandContext(ctx, gitBin, args...)
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if err == nil {
		nativeCapabilityCache.Store(gitBin, true)
		return true, nil
	}
	detail := strings.TrimSpace(stderr.String())
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && nativeUnsupportedFlag(detail) {
		nativeCapabilityCache.Store(gitBin, false)
		return false, nil
	}
	if detail != "" {
		return false, fmt.Errorf("git: native capability probe: %w: %s", err, detail)
	}
	return false, fmt.Errorf("git: native capability probe: %w", err)
}

func nativeUnsupportedFlag(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "unknown option") ||
		strings.Contains(lower, "unknown switch") ||
		strings.Contains(lower, "unrecognized option") ||
		strings.Contains(lower, "unrecognized argument")
}

func nativeGitEnv() []string {
	blocked := map[string]struct{}{
		"GIT_DIR": {}, "GIT_WORK_TREE": {}, "GIT_COMMON_DIR": {},
		"GIT_OBJECT_DIRECTORY": {}, "GIT_ALTERNATE_OBJECT_DIRECTORIES": {},
		"GIT_INDEX_FILE": {}, "GIT_PREFIX": {}, "GIT_NAMESPACE": {},
		"GIT_SHALLOW_FILE": {}, "GIT_OPTIONAL_LOCKS": {},
		"GIT_TERMINAL_PROMPT": {}, "GIT_NO_LAZY_FETCH": {},
		"GIT_NO_REPLACE_OBJECTS": {},
		"GIT_CONFIG_COUNT":       {}, "GIT_CONFIG_PARAMETERS": {},
		"GIT_CONFIG_SYSTEM": {}, "GIT_CONFIG_GLOBAL": {},
		"GIT_DIFF_OPTS": {}, "GIT_EXTERNAL_DIFF": {},
		"GIT_GLOB_PATHSPECS": {}, "GIT_NOGLOB_PATHSPECS": {},
		"GIT_LITERAL_PATHSPECS": {}, "GIT_EXEC_PATH": {},
		"LC_ALL": {}, "LANG": {}, "LANGUAGE": {},
	}
	env := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		_, drop := blocked[key]
		if strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") || strings.HasPrefix(key, "GIT_TRACE") {
			drop = true
		}
		if !drop {
			env = append(env, entry)
		}
	}
	return append(env,
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_LITERAL_PATHSPECS=1",
		"LC_ALL=C",
		"LANG=C",
	)
}

// chunksNative streams the entire selected history through one native git
// process. Once started it never falls back to go-git: doing so after an
// emitted chunk would duplicate findings and could advance the checkpoint
// across a partially covered walk.
func (s *Source) chunksNative(ctx context.Context, repo *gogit.Repository, gitBin string, starts, stops []plumbing.Hash, ch chan<- *sources.Chunk) error {
	cmd := exec.CommandContext(ctx, gitBin, s.nativeLogArgs()...)
	cmd.Stdin = strings.NewReader(nativeRevisionInput(starts, stops))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git: native log stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git: start native log: %w", err)
	}

	mergePass, err := s.startNativeMergeResults(ctx, gitBin)
	if err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return err
	}

	parser := nativeLogParser{
		ctx:        ctx,
		source:     s,
		repo:       repo,
		gitBin:     gitBin,
		ch:         ch,
		mergeInput: mergePass.stdin,
	}
	parseErr := parser.parse(stdout)
	mergeCloseErr := mergePass.closeInput()
	if parseErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		mergePass.abort()
		return err
	}
	if parseErr != nil {
		mergePass.abort()
		return parser.walkError(fmt.Errorf("git: parse native log: %w", parseErr))
	}
	if waitErr != nil {
		mergePass.abort()
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return parser.walkError(fmt.Errorf("git: native log: %w: %s", waitErr, detail))
		}
		return parser.walkError(fmt.Errorf("git: native log: %w", waitErr))
	}
	if mergeCloseErr != nil {
		mergePass.abort()
		return fmt.Errorf("git: close native merge input: %w", mergeCloseErr)
	}
	return mergePass.finish(ctx, s, repo, gitBin, ch)
}

func (s *Source) nativeLogArgs() []string {
	// Reverse topological order is deterministic and always emits a parent
	// before its child. The go-git fallback's stable timestamp sort can invert
	// that relation when commit clocks are skewed; the native path deliberately
	// corrects that artifact while preserving the commit and finding sets.
	args := []string{
		"-c", "diff.suppressBlankEmpty=false",
		"-C", s.repoAbs,
		"log",
		"--patch",
		"--root",
		"--reverse",
		"--topo-order",
		"--full-history",
		"--no-show-signature",
		"--raw",
		"--abbrev=40",
		"--no-renames",
		"--no-color",
		"--no-ext-diff",
		"--no-textconv",
		"--no-indent-heuristic",
		"--inter-hunk-context=0",
		"--ignore-submodules=all",
		"--diff-algorithm=myers",
		// Merge commits are handled by a separate raw-tree pass below. Asking
		// git-log to render merge patches repeats side-branch history and makes
		// large monorepos spend hours formatting duplicate diffs.
		"--diff-merges=off",
		"--unified=3",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--format=" + nativePrettyFormat,
	}
	if s.maxDepth > 0 {
		args = append(args, "--max-count="+strconv.Itoa(s.maxDepth))
	}
	if !s.since.IsZero() {
		args = append(args, "--since-as-filter=@"+strconv.FormatInt(s.since.Unix(), 10))
	}
	return append(args, "--stdin", "--")
}

// nativeMergePass computes combined patches while the main patch stream is
// being parsed. Its stdout is spooled to a private temporary file so merge
// resolution chunks remain ordered after all ordinary-history chunks.
type nativeMergePass struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	output *os.File
	stderr limitedWriter
	closed bool
}

// startNativeMergeResults covers content introduced by merge conflict
// resolution without asking git-log to render every merge patch. The main
// patch parser streams selected merge IDs into diff-tree, so tree comparison
// overlaps the ordinary patch walk and never traverses history a second time.
func (s *Source) startNativeMergeResults(ctx context.Context, gitBin string) (*nativeMergePass, error) {
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
		"-c",
		"--unified=3",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--format=" + nativePrettyFormat,
		"--",
	}

	cmd := exec.CommandContext(ctx, gitBin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: native merge raw stdin: %w", err)
	}
	output, err := os.CreateTemp("", "pleno-dlp-native-merge-*.patch")
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("git: create native merge spool: %w", err)
	}
	pass := &nativeMergePass{cmd: cmd, stdin: stdin, output: output}
	pass.stderr.limit = nativeStderrLimit
	cmd.Stdout = output
	cmd.Stderr = &pass.stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = output.Close()
		_ = os.Remove(output.Name())
		return nil, fmt.Errorf("git: start native merge raw: %w", err)
	}
	return pass, nil
}

func (p *nativeMergePass) closeInput() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return p.stdin.Close()
}

func (p *nativeMergePass) cleanup() {
	_ = p.output.Close()
	_ = os.Remove(p.output.Name())
}

func (p *nativeMergePass) abort() {
	_ = p.closeInput()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
	p.cleanup()
}

func (p *nativeMergePass) finish(ctx context.Context, source *Source, repo *gogit.Repository, gitBin string, ch chan<- *sources.Chunk) error {
	waitErr := p.cmd.Wait()
	if err := ctx.Err(); err != nil {
		p.cleanup()
		return err
	}
	if waitErr != nil {
		detail := strings.TrimSpace(p.stderr.String())
		p.cleanup()
		if detail != "" {
			return fmt.Errorf("git: native merge raw: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("git: native merge raw: %w", waitErr)
	}
	if _, err := p.output.Seek(0, io.SeekStart); err != nil {
		p.cleanup()
		return fmt.Errorf("git: rewind native merge spool: %w", err)
	}
	parseErr := source.parseNativeMergeResults(ctx, repo, gitBin, p.output, ch)
	p.cleanup()
	if parseErr != nil {
		return fmt.Errorf("git: parse native merge patch: %w", parseErr)
	}
	return nil
}

func (s *Source) parseNativeMergeResults(ctx context.Context, repo *gogit.Repository, gitBin string, r io.Reader, ch chan<- *sources.Chunk) error {
	reader := bufio.NewReaderSize(r, 256<<10)
	parser := nativeLogParser{ctx: ctx, source: s, repo: repo, gitBin: gitBin, ch: ch}
	for {
		line, truncated, err := readNativeLine(reader, int(maxBlobSize)+1)
		if truncated {
			return fmt.Errorf("native merge patch line exceeds %d-byte limit", maxBlobSize)
		}
		if len(line) > 0 {
			switch {
			case line[0] == nativeRecordSeparator:
				if parseErr := parser.consumeLine(line); parseErr != nil {
					return parseErr
				}
			case line[0] == ':' && bytes.HasPrefix(line, []byte("::")):
				if parser.commit == nil {
					return errors.New("native merge raw record precedes commit metadata")
				}
				path, deleted, parseErr := parseNativeCombinedRawPath(line)
				if parseErr != nil {
					return parseErr
				}
				if len(parser.rawPaths) >= nativePathLimit || parser.rawPathBytes+int64(len(path)) > maxBlobSize {
					return fmt.Errorf("native merge raw paths exceed %d entries or %d bytes", nativePathLimit, maxBlobSize)
				}
				parser.rawPaths = append(parser.rawPaths, path)
				parser.rawDeleted = append(parser.rawDeleted, deleted)
				parser.rawPathBytes += int64(len(path))
			case bytes.HasPrefix(line, []byte("diff --combined ")) || bytes.HasPrefix(line, []byte("diff --cc ")):
				if parseErr := parser.consumeLine([]byte("diff --git \n")); parseErr != nil {
					return parseErr
				}
			case parser.commit != nil && isNativeCombinedHunkHeader(line, parser.commit.parentCount):
				if parseErr := parser.flushHunk(); parseErr != nil {
					return parseErr
				}
				start, ok := nativeCombinedHunkStart(line, parser.commit.parentCount)
				if !ok {
					return fmt.Errorf("malformed native combined hunk header %q", strings.TrimSpace(string(line)))
				}
				parser.hunk = nativeHunk{newLine: start}
				parser.inHunk = true
			case parser.inHunk:
				synthetic, parseErr := nativeCombinedResultLine(line, parser.commit.parentCount)
				if parseErr != nil {
					return parseErr
				}
				if parseErr := parser.consumeLine(synthetic); parseErr != nil {
					return parseErr
				}
			default:
				if parseErr := parser.consumeLine(line); parseErr != nil {
					return parseErr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return parser.flushFile()
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func isNativeCombinedHunkHeader(line []byte, parents int) bool {
	if parents < 2 {
		return false
	}
	return bytes.HasPrefix(line, []byte(strings.Repeat("@", parents+1)+" "))
}

func nativeCombinedHunkStart(line []byte, parents int) (int, bool) {
	if !isNativeCombinedHunkHeader(line, parents) {
		return 0, false
	}
	fields := bytes.Fields(line)
	if len(fields) < parents+3 {
		return 0, false
	}
	resultRange := fields[parents+1]
	if len(resultRange) < 2 || resultRange[0] != '+' {
		return 0, false
	}
	end := bytes.IndexByte(resultRange, ',')
	if end < 0 {
		end = len(resultRange)
	}
	start, err := strconv.Atoi(string(resultRange[1:end]))
	return start, err == nil
}

func nativeCombinedResultLine(line []byte, parents int) ([]byte, error) {
	if len(line) > 0 && line[0] == '\\' {
		return line, nil
	}
	if parents < 2 || len(line) < parents {
		return nil, fmt.Errorf("malformed native combined patch line %q", strings.TrimSpace(string(line)))
	}
	prefix := line[:parents]
	marker := byte(' ')
	allAdded := true
	for _, column := range prefix {
		switch column {
		case '-':
			marker = '-'
			allAdded = false
		case '+':
		case ' ':
			allAdded = false
		default:
			return nil, fmt.Errorf("malformed native combined patch prefix %q", string(prefix))
		}
	}
	if marker != '-' && allAdded {
		marker = '+'
	}
	synthetic := make([]byte, 1, len(line)-parents+1)
	synthetic[0] = marker
	return append(synthetic, line[parents:]...), nil
}

func parseNativeCombinedRawPath(line []byte) (path string, deleted bool, err error) {
	tab := bytes.IndexByte(line, '\t')
	if tab < 0 {
		return "", false, fmt.Errorf("malformed native combined raw record %q", strings.TrimSpace(string(line)))
	}
	fields := bytes.Fields(line[:tab])
	if len(fields) < 2 {
		return "", false, fmt.Errorf("malformed native combined raw record %q", strings.TrimSpace(string(line)))
	}
	status := fields[len(fields)-1]
	deleted = len(status) > 0
	for _, marker := range status {
		deleted = deleted && marker == 'D'
	}
	raw := bytes.TrimSuffix(line[tab+1:], []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	path = string(raw)
	if strings.HasPrefix(path, "\"") {
		path, err = strconv.Unquote(path)
		if err != nil {
			return "", false, fmt.Errorf("malformed native combined raw path %q: %w", string(raw), err)
		}
	}
	return path, deleted, nil
}

func nativeRevisionInput(starts, stops []plumbing.Hash) string {
	var input strings.Builder
	for _, start := range starts {
		if start != plumbing.ZeroHash {
			fmt.Fprintln(&input, start)
		}
	}
	for _, stop := range stops {
		if stop != plumbing.ZeroHash {
			fmt.Fprintf(&input, "^%s\n", stop)
		}
	}
	return input.String()
}

func nativeExistingStops(ctx context.Context, repo *gogit.Repository, stops []plumbing.Hash) ([]plumbing.Hash, error) {
	existing := make([]plumbing.Hash, 0, len(stops))
	for _, stop := range stops {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if stop == plumbing.ZeroHash {
			continue
		}
		if _, err := repo.CommitObject(stop); err != nil {
			if errors.Is(err, plumbing.ErrObjectNotFound) {
				continue
			}
			return nil, fmt.Errorf("git: resolve previous head %s: %w", stop, err)
		}
		existing = append(existing, stop)
	}
	return existing, nil
}

func (s *Source) retainPreviousState() {
	if s.previousState == nil {
		return
	}
	previous := *s.previousState
	previous.Heads = append([]string(nil), s.previousState.Heads...)
	s.nextState = &previous
}

func (s *Source) nativeDegradedError(err error) error {
	source := s.repoAbs + "@native-log"
	var walkErr *nativeWalkError
	if errors.As(err, &walkErr) && walkErr.commit != "" {
		source = fmt.Sprintf("%s@%s:%s", s.repoAbs, walkErr.commit, walkErr.stage)
	}
	return &engine.DegradedError{
		Total:  1,
		Counts: map[engine.FailureKind]int{engine.FailureSource: 1},
		Failures: []engine.ScanFailure{{
			Kind:   engine.FailureSource,
			Source: source,
			Err:    err,
		}},
	}
}

type nativeWalkError struct {
	commit string
	stage  string
	err    error
}

func (e *nativeWalkError) Error() string { return e.err.Error() }
func (e *nativeWalkError) Unwrap() error { return e.err }

type nativeCommit struct {
	hash         string
	parentCount  int
	author       string
	email        string
	authoredDate string
	message      string
}

type nativeFilePatch struct {
	path             string
	newFile          bool
	deleted          bool
	segments         []diffSegment
	totalBytes       int64
	hasAdd           bool
	binary           bool
	streaming        bool
	overLimit        bool
	overSegmentLimit bool
}

type nativeHunk struct {
	data           []byte
	newLine        int
	firstAddLine   int
	hasAdd         bool
	binary         bool
	lastWasNewSide bool
	overLimit      bool
}

type nativeLogParser struct {
	ctx    context.Context
	source *Source
	repo   *gogit.Repository
	gitBin string
	ch     chan<- *sources.Chunk

	commit       *nativeCommit
	file         nativeFilePatch
	hunk         nativeHunk
	inHunk       bool
	rawPaths     []string
	rawDeleted   []bool
	rawPathBytes int64
	rawIndex     int
	bufferLimit  int64
	mergeInput   io.Writer
}

func (p *nativeLogParser) walkError(err error) error {
	commit := ""
	if p.commit != nil {
		commit = p.commit.hash
	}
	if commit == "" {
		return err
	}
	stage := "tree-diff"
	if tree := missingTreeHash(err.Error()); tree != plumbing.ZeroHash {
		stage += "/" + tree.String()
	}
	return &nativeWalkError{commit: commit, stage: stage, err: err}
}

func missingTreeHash(message string) plumbing.Hash {
	for _, prefix := range []string{"unable to read tree (", "bad tree object "} {
		start := strings.Index(message, prefix)
		if start < 0 {
			continue
		}
		start += len(prefix)
		if len(message)-start < 40 {
			continue
		}
		raw := message[start : start+40]
		if _, err := hex.DecodeString(raw); err == nil {
			return plumbing.NewHash(raw)
		}
	}
	return plumbing.ZeroHash
}

func (p *nativeLogParser) parse(r io.Reader) error {
	reader := bufio.NewReaderSize(r, 256<<10)
	for {
		line, truncated, err := readNativeLine(reader, int(maxBlobSize)+1)
		if len(line) > 0 {
			if truncated {
				if parseErr := p.consumeTruncatedLine(line); parseErr != nil {
					return parseErr
				}
			} else if parseErr := p.consumeLine(line); parseErr != nil {
				return parseErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if err := p.ctx.Err(); err != nil {
			return err
		}
	}
	return p.flushFile()
}

func readNativeLine(reader *bufio.Reader, limit int) ([]byte, bool, error) {
	if limit < 1 {
		return nil, false, errors.New("native line limit must be positive")
	}
	fragment, err := reader.ReadSlice('\n')
	if !errors.Is(err, bufio.ErrBufferFull) {
		if len(fragment) > limit {
			return fragment[:limit], true, err
		}
		return fragment, false, err
	}
	line := make([]byte, 0, min(limit, 2*len(fragment)))
	truncated := false
	for {
		if remaining := limit - len(line); remaining > 0 {
			if remaining > len(fragment) {
				remaining = len(fragment)
			}
			line = append(line, fragment[:remaining]...)
			if remaining < len(fragment) {
				truncated = true
			}
		} else if len(fragment) > 0 {
			truncated = true
		}
		fragment, err = reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if remaining := limit - len(line); remaining > 0 {
			if remaining > len(fragment) {
				remaining = len(fragment)
			}
			line = append(line, fragment[:remaining]...)
			if remaining < len(fragment) {
				truncated = true
			}
		} else if len(fragment) > 0 {
			truncated = true
		}
		return line, truncated, err
	}
}

func (p *nativeLogParser) consumeTruncatedLine(line []byte) error {
	if !p.inHunk || len(line) == 0 {
		return fmt.Errorf("native output line exceeds %d-byte limit", maxBlobSize)
	}
	switch line[0] {
	case '+':
		p.hunk.hasAdd = true
		if p.hunk.firstAddLine == 0 {
			p.hunk.firstAddLine = p.hunk.newLine
		}
		p.hunk.binary = p.hunk.binary || bytes.IndexByte(line[1:], 0x00) >= 0
		p.hunk.data = nil
		p.hunk.overLimit = true
		p.hunk.newLine++
		p.hunk.lastWasNewSide = true
	case ' ':
		p.hunk.binary = p.hunk.binary || bytes.IndexByte(line[1:], 0x00) >= 0
		p.hunk.data = nil
		p.hunk.overLimit = true
		p.hunk.newLine++
		p.hunk.lastWasNewSide = true
	case '-':
		p.hunk.lastWasNewSide = false
	default:
		return fmt.Errorf("native output line exceeds %d-byte limit", maxBlobSize)
	}
	return nil
}

func (p *nativeLogParser) consumeLine(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	if line[0] == nativeRecordSeparator {
		if err := p.flushFile(); err != nil {
			return err
		}
		commit, err := parseNativeCommit(line)
		if err != nil {
			return err
		}
		p.commit = &commit
		if commit.parentCount > 1 && p.mergeInput != nil {
			if _, err := fmt.Fprintln(p.mergeInput, commit.hash); err != nil {
				return fmt.Errorf("write native merge hash: %w", err)
			}
		}
		p.rawPaths = nil
		p.rawDeleted = nil
		p.rawPathBytes = 0
		p.rawIndex = 0
		return nil
	}
	if line[0] == ':' {
		path, deleted, err := parseNativeRawPath(line)
		if err != nil {
			return err
		}
		if len(p.rawPaths) >= nativePathLimit || p.rawPathBytes+int64(len(path)) > maxBlobSize {
			return fmt.Errorf("native raw diff paths exceed %d entries or %d bytes", nativePathLimit, maxBlobSize)
		}
		p.rawPaths = append(p.rawPaths, path)
		p.rawDeleted = append(p.rawDeleted, deleted)
		p.rawPathBytes += int64(len(path))
		return nil
	}
	if bytes.HasPrefix(line, []byte("diff --git ")) {
		if err := p.flushFile(); err != nil {
			return err
		}
		p.file = nativeFilePatch{}
		if p.rawIndex < len(p.rawPaths) {
			p.file.path = p.rawPaths[p.rawIndex]
			p.file.deleted = p.rawDeleted[p.rawIndex]
			p.rawIndex++
		}
		return nil
	}
	if !p.inHunk && bytes.HasPrefix(line, []byte("--- ")) {
		path, isNull, err := parseNativePatchPath(line[4:], "a/")
		if err != nil {
			return err
		}
		p.file.newFile = isNull
		if !isNull && p.file.path == "" {
			p.file.path = path
		}
		return nil
	}
	if !p.inHunk && bytes.HasPrefix(line, []byte("+++ ")) {
		path, isNull, err := parseNativePatchPath(line[4:], "b/")
		if err != nil {
			return err
		}
		if isNull {
			p.file.path = ""
		} else {
			p.file.path = path
		}
		return nil
	}
	if bytes.HasPrefix(line, []byte("@@ ")) {
		if err := p.flushHunk(); err != nil {
			return err
		}
		start, ok := newHunkStart(string(line))
		if !ok {
			return fmt.Errorf("malformed native hunk header %q", strings.TrimSpace(string(line)))
		}
		p.hunk = nativeHunk{newLine: start}
		p.inHunk = true
		return nil
	}
	if bytes.HasPrefix(line, []byte("Binary files ")) && bytes.HasSuffix(bytes.TrimSpace(line), []byte(" differ")) {
		return p.handleBinaryPatch()
	}
	if !p.inHunk {
		return nil
	}
	switch line[0] {
	case '+':
		p.hunk.hasAdd = true
		if p.hunk.firstAddLine == 0 {
			p.hunk.firstAddLine = p.hunk.newLine
		}
		p.hunk.append(line[1:])
		p.hunk.newLine++
		p.hunk.lastWasNewSide = true
	case ' ':
		p.hunk.append(line[1:])
		p.hunk.newLine++
		p.hunk.lastWasNewSide = true
	case '-':
		p.hunk.lastWasNewSide = false
	case '\\':
		if p.hunk.lastWasNewSide && len(p.hunk.data) > 0 && p.hunk.data[len(p.hunk.data)-1] == '\n' {
			p.hunk.data = p.hunk.data[:len(p.hunk.data)-1]
		}
	default:
		p.inHunk = false
	}
	return nil
}

func (h *nativeHunk) append(data []byte) {
	h.binary = h.binary || bytes.IndexByte(data, 0x00) >= 0
	if h.overLimit {
		return
	}
	if int64(len(h.data))+int64(len(data)) > maxBlobSize {
		h.data = nil
		h.overLimit = true
		return
	}
	h.data = append(h.data, data...)
}

func (p *nativeLogParser) flushHunk() error {
	if !p.inHunk {
		return nil
	}
	p.inHunk = false
	p.file.binary = p.file.binary || p.hunk.binary
	if !p.hunk.hasAdd {
		p.hunk = nativeHunk{}
		return nil
	}
	if p.hunk.overLimit {
		p.file.overLimit = true
		p.file.segments = nil
		p.hunk = nativeHunk{}
		return nil
	}
	if err := p.appendFile(p.hunk.data, p.hunk.firstAddLine); err != nil {
		return err
	}
	p.hunk = nativeHunk{}
	return nil
}

func (p *nativeLogParser) appendFile(data []byte, firstLine int) error {
	f := &p.file
	if f.overLimit || f.overSegmentLimit {
		return nil
	}
	f.hasAdd = true
	segments := splitNativePatch(data, firstLine)
	if f.streaming {
		return p.emitSegments(f.path, segments)
	}
	limit := p.bufferLimit
	if limit == 0 {
		limit = maxBlobSize
	}
	if f.totalBytes+int64(len(data)) > limit {
		if f.path == "" || p.commit == nil || !p.source.pathAllowed(f.path) {
			f.segments = nil
			f.streaming = true
			return nil
		}
		binary, err := p.currentFileBinary()
		if err != nil {
			return err
		}
		if binary {
			f.segments = nil
			f.binary = true
			return nil
		}
		f.streaming = true
		buffered := f.segments
		f.segments = nil
		if err := p.emitSegments(f.path, buffered); err != nil {
			return err
		}
		return p.emitSegments(f.path, segments)
	}
	f.totalBytes += int64(len(data))
	if len(f.segments)+len(segments) > nativeSegmentLimit {
		f.segments = nil
		f.overSegmentLimit = true
		return nil
	}
	f.segments = append(f.segments, segments...)
	return nil
}

func (p *nativeLogParser) currentFileBinary() (binary bool, err error) {
	if p.gitBin != "" {
		return p.currentFileBinaryNative()
	}
	commit, err := p.repo.CommitObject(plumbing.NewHash(p.commit.hash))
	if err != nil {
		return false, fmt.Errorf("load commit %s for binary classification: %w", p.commit.hash, err)
	}
	file, err := commit.File(p.file.path)
	if err != nil {
		return false, fmt.Errorf("load %s at %s for binary classification: %w", p.file.path, p.commit.hash, err)
	}
	reader, err := file.Reader()
	if err != nil {
		return false, fmt.Errorf("open %s at %s for binary classification: %w", p.file.path, p.commit.hash, err)
	}
	defer func() {
		if closeErr := reader.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %s at %s after binary classification: %w", p.file.path, p.commit.hash, closeErr)
		}
	}()
	binary, readErr := readerContainsNUL(p.ctx, reader)
	if readErr != nil {
		return false, fmt.Errorf("read %s at %s for binary classification: %w", p.file.path, p.commit.hash, readErr)
	}
	return binary, nil
}

func (p *nativeLogParser) currentFileBinaryNative() (bool, error) {
	object := p.commit.hash + ":" + p.file.path
	cmd := exec.CommandContext(p.ctx, p.gitBin, "-C", p.source.repoAbs, "cat-file", "blob", object)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, fmt.Errorf("git: native binary classification stdout for %s: %w", p.file.path, err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("git: start native binary classification for %s: %w", p.file.path, err)
	}
	binary, readErr := readerContainsNUL(p.ctx, stdout)
	if binary || readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if readErr != nil {
			return false, fmt.Errorf("git: read native binary classification for %s: %w", p.file.path, readErr)
		}
		return true, nil
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return false, fmt.Errorf("git: native binary classification for %s: %w: %s", p.file.path, waitErr, detail)
		}
		return false, fmt.Errorf("git: native binary classification for %s: %w", p.file.path, waitErr)
	}
	return false, nil
}

func readerContainsNUL(ctx context.Context, reader io.Reader) (bool, error) {
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, readErr := reader.Read(buf)
		if bytes.IndexByte(buf[:n], 0x00) >= 0 {
			return true, nil
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return false, nil
			}
			return false, readErr
		}
	}
}

func (p *nativeLogParser) flushFile() error {
	if err := p.flushHunk(); err != nil {
		return err
	}
	file := p.file
	p.file = nativeFilePatch{}
	if file.path == "" || p.commit == nil || file.binary {
		return nil
	}
	if file.overSegmentLimit {
		return fmt.Errorf("native diff for %s at %s exceeds %d segments", file.path, p.commit.hash, nativeSegmentLimit)
	}
	if !file.hasAdd {
		return nil
	}
	if file.overLimit {
		if file.newFile {
			return nil
		}
		return fmt.Errorf("added diff content for %s at %s exceeds %d-byte limit", file.path, p.commit.hash, maxBlobSize)
	}
	if file.streaming || !p.source.pathAllowed(file.path) || len(file.segments) == 0 {
		return nil
	}
	return p.emitSegments(file.path, file.segments)
}

func (p *nativeLogParser) emitSegments(path string, segments []diffSegment) error {
	for _, segment := range segments {
		chunk := &sources.Chunk{
			SourceID:   p.source.sourceID,
			SourceType: sources.SourceGit,
			SourceName: p.source.name,
			Data:       segment.data,
			SourceMetadata: sources.Metadata{Git: &sources.GitMeta{
				Repository:   p.source.repoAbs,
				Commit:       p.commit.hash,
				File:         path,
				Line:         segment.line,
				Email:        p.commit.email,
				Author:       p.commit.author,
				AuthoredDate: p.commit.authoredDate,
				Message:      p.commit.message,
			}},
		}
		select {
		case p.ch <- chunk:
		case <-p.ctx.Done():
			return p.ctx.Err()
		}
	}
	return nil
}

func (p *nativeLogParser) handleBinaryPatch() error {
	if p.file.path == "" || p.commit == nil {
		return nil
	}
	if p.file.deleted {
		p.file.binary = true
		return nil
	}
	commit, err := p.repo.CommitObject(plumbing.NewHash(p.commit.hash))
	if err != nil {
		return fmt.Errorf("load commit %s for binary classification: %w", p.commit.hash, err)
	}
	file, err := commit.File(p.file.path)
	if err != nil {
		return fmt.Errorf("load %s at %s for binary classification: %w", p.file.path, p.commit.hash, err)
	}
	binary, err := file.IsBinary()
	if err != nil {
		return fmt.Errorf("classify %s at %s as binary: %w", p.file.path, p.commit.hash, err)
	}
	if binary {
		p.file.binary = true
		return nil
	}
	return p.emitForcedTextPatch(p.file.path)
}

func (p *nativeLogParser) emitForcedTextPatch(path string) error {
	args := []string{
		"-c", "diff.suppressBlankEmpty=false",
		"-C", p.source.repoAbs,
		"show",
		"--format=",
		"--patch",
		"--root",
		"--no-show-signature",
		"--no-renames",
		"--text",
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
		p.commit.hash,
		"--",
		path,
	}
	cmd := exec.CommandContext(p.ctx, p.gitBin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("forced text diff stdout: %w", err)
	}
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Env = nativeGitEnv()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start forced text diff: %w", err)
	}
	parser := nativeLogParser{ctx: p.ctx, source: p.source, repo: p.repo, gitBin: p.gitBin, ch: p.ch, commit: p.commit}
	parseErr := parser.parse(stdout)
	if parseErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil {
		return fmt.Errorf("parse forced text diff: %w", parseErr)
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("forced text diff: %w: %s", waitErr, detail)
		}
		return fmt.Errorf("forced text diff: %w", waitErr)
	}
	return nil
}

func splitNativePatch(data []byte, firstLine int) []diffSegment {
	if len(data) <= maxDiffChunkSize {
		return []diffSegment{{data: data, line: firstLine}}
	}
	var out []diffSegment
	start, line := 0, firstLine
	for start < len(data) {
		end := start + maxDiffChunkSize
		if end > len(data) {
			end = len(data)
		}
		out = append(out, diffSegment{data: data[start:end], line: line})
		if end == len(data) {
			break
		}
		next := end - diffChunkOverlap
		line += bytes.Count(data[start:next], []byte{'\n'})
		start = next
	}
	return out
}

func parseNativeCommit(line []byte) (nativeCommit, error) {
	record := bytes.TrimSuffix(line, []byte{'\n'})
	record = bytes.TrimSuffix(record, []byte{'\r'})
	if len(record) == 0 || record[0] != nativeRecordSeparator || record[len(record)-1] != nativeFieldSeparator {
		return nativeCommit{}, errors.New("malformed native commit record")
	}
	fields := bytes.Split(record[1:len(record)-1], []byte{nativeFieldSeparator})
	if len(fields) != 6 {
		return nativeCommit{}, fmt.Errorf("malformed native commit record: got %d fields", len(fields))
	}
	hash := string(fields[0])
	if len(hash) != 40 {
		return nativeCommit{}, fmt.Errorf("malformed native commit hash %q", hash)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return nativeCommit{}, fmt.Errorf("malformed native commit hash %q: %w", hash, err)
	}
	parents := bytes.Fields(fields[1])
	for _, parent := range parents {
		if len(parent) != 40 {
			return nativeCommit{}, fmt.Errorf("malformed native parent hash %q", parent)
		}
		if _, err := hex.DecodeString(string(parent)); err != nil {
			return nativeCommit{}, fmt.Errorf("malformed native parent hash %q: %w", parent, err)
		}
	}
	authored, err := time.Parse(time.RFC3339, string(fields[4]))
	if err != nil {
		return nativeCommit{}, fmt.Errorf("malformed native authored date %q: %w", fields[4], err)
	}
	return nativeCommit{
		hash:         hash,
		parentCount:  len(parents),
		author:       string(fields[2]),
		email:        string(fields[3]),
		authoredDate: authored.UTC().Format(time.RFC3339),
		message:      string(fields[5]),
	}, nil
}

func parseNativePatchPath(raw []byte, prefix string) (string, bool, error) {
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	text := string(raw)
	if text == "/dev/null" {
		return "", true, nil
	}
	text = strings.TrimSuffix(text, "\t")
	if strings.HasPrefix(text, "\"") {
		unquoted, err := strconv.Unquote(text)
		if err != nil {
			return "", false, fmt.Errorf("malformed native patch path %q: %w", text, err)
		}
		text = unquoted
	}
	if !strings.HasPrefix(text, prefix) {
		return "", false, fmt.Errorf("native patch path %q lacks %q prefix", text, prefix)
	}
	return strings.TrimPrefix(text, prefix), false, nil
}

func parseNativeRawPath(line []byte) (string, bool, error) {
	tab := bytes.IndexByte(line, '\t')
	if tab < 0 {
		return "", false, fmt.Errorf("malformed native raw diff record %q", strings.TrimSpace(string(line)))
	}
	fields := bytes.Fields(line[:tab])
	if len(fields) == 0 {
		return "", false, fmt.Errorf("malformed native raw diff record %q", strings.TrimSpace(string(line)))
	}
	raw := bytes.TrimSuffix(line[tab+1:], []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	path := string(raw)
	if strings.HasPrefix(path, "\"") {
		unquoted, err := strconv.Unquote(path)
		if err != nil {
			return "", false, fmt.Errorf("malformed native raw diff path %q: %w", path, err)
		}
		path = unquoted
	}
	return path, fields[len(fields)-1][0] == 'D', nil
}

type limitedWriter struct {
	buf   bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	return n, nil
}

func (w *limitedWriter) String() string { return w.buf.String() }
