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
	nativePrettyFormat    = "%x1e%H%x00%an%x00%ae%x00%aI%x00%s%x00%P%x00"
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
		"--diff-merges=first-parent",
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
	cmd := exec.CommandContext(ctx, gitBin, s.nativeLogArgs(starts, stops)...)
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

	parser := nativeLogParser{ctx: ctx, source: s, repo: repo, gitBin: gitBin, ch: ch}
	parseErr := parser.parse(stdout)
	if parseErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if parseErr != nil {
		return parser.walkError(fmt.Errorf("git: parse native log: %w", parseErr))
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return parser.walkError(fmt.Errorf("git: native log: %w: %s", waitErr, detail))
		}
		return parser.walkError(fmt.Errorf("git: native log: %w", waitErr))
	}
	return nil
}

func (s *Source) nativeLogArgs(starts, stops []plumbing.Hash) []string {
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
		"--diff-merges=first-parent",
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
	author       string
	email        string
	authoredDate string
	message      string
}

type nativeFilePatch struct {
	path             string
	newFile          bool
	segments         []diffSegment
	totalBytes       int64
	hasAdd           bool
	binary           bool
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
	rawPathBytes int64
	rawIndex     int
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
		p.rawPaths = nil
		p.rawPathBytes = 0
		p.rawIndex = 0
		return nil
	}
	if line[0] == ':' {
		path, err := parseNativeRawPath(line)
		if err != nil {
			return err
		}
		if len(p.rawPaths) >= nativePathLimit || p.rawPathBytes+int64(len(path)) > maxBlobSize {
			return fmt.Errorf("native raw diff paths exceed %d entries or %d bytes", nativePathLimit, maxBlobSize)
		}
		p.rawPaths = append(p.rawPaths, path)
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
			p.rawIndex++
		}
		return nil
	}
	if bytes.HasPrefix(line, []byte("--- ")) {
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
	if bytes.HasPrefix(line, []byte("+++ ")) {
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
	p.file.append(p.hunk.data, p.hunk.firstAddLine)
	p.hunk = nativeHunk{}
	return nil
}

func (f *nativeFilePatch) append(data []byte, firstLine int) {
	if f.overLimit || f.overSegmentLimit {
		return
	}
	if f.totalBytes+int64(len(data)) > maxBlobSize {
		f.segments = nil
		f.overLimit = true
		return
	}
	f.totalBytes += int64(len(data))
	f.hasAdd = true
	segments := splitNativePatch(data, firstLine)
	if len(f.segments)+len(segments) > nativeSegmentLimit {
		f.segments = nil
		f.overSegmentLimit = true
		return
	}
	f.segments = append(f.segments, segments...)
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
	if !p.source.pathAllowed(file.path) || len(file.segments) == 0 {
		return nil
	}
	for _, segment := range file.segments {
		chunk := &sources.Chunk{
			SourceID:   p.source.sourceID,
			SourceType: sources.SourceGit,
			SourceName: p.source.name,
			Data:       segment.data,
			SourceMetadata: sources.Metadata{Git: &sources.GitMeta{
				Repository:   p.source.repoAbs,
				Commit:       p.commit.hash,
				File:         file.path,
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
		"--diff-merges=first-parent",
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
	authored, err := time.Parse(time.RFC3339, string(fields[3]))
	if err != nil {
		return nativeCommit{}, fmt.Errorf("malformed native authored date %q: %w", fields[3], err)
	}
	return nativeCommit{
		hash:         hash,
		author:       string(fields[1]),
		email:        string(fields[2]),
		authoredDate: authored.UTC().Format(time.RFC3339),
		message:      string(fields[4]),
	}, nil
}

func parseNativePatchPath(raw []byte, prefix string) (string, bool, error) {
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	text := string(raw)
	if text == "/dev/null" {
		return "", true, nil
	}
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

func parseNativeRawPath(line []byte) (string, error) {
	tab := bytes.IndexByte(line, '\t')
	if tab < 0 {
		return "", fmt.Errorf("malformed native raw diff record %q", strings.TrimSpace(string(line)))
	}
	raw := bytes.TrimSuffix(line[tab+1:], []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	path := string(raw)
	if strings.HasPrefix(path, "\"") {
		unquoted, err := strconv.Unquote(path)
		if err != nil {
			return "", fmt.Errorf("malformed native raw diff path %q: %w", path, err)
		}
		path = unquoted
	}
	return path, nil
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
