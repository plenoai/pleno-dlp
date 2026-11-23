package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// In-process patch rendering (#983).
//
// `git log -p` spends most of its CPU re-reading and re-diffing blobs; the
// native walk instead asks git only for the raw tree diff (`git log --raw`)
// and renders each file patch itself from blobs read once over a persistent
// `git cat-file --batch`, with xdiff.go reproducing git's Myers hunks. The
// rendered stream is byte-identical to what `git log -p` would print for the
// same arguments, so the existing nativeLogParser (attribution, hunk windows,
// binary handling, replicas) consumes it unchanged. Anything the renderer
// does not model exactly — gitlinks, renames/copies, diff drivers with
// configured binary settings, oversized blobs, unreadable objects — makes
// that one commit fall back to a real `git log -p` rendering.

// nativeSynthMaxBlob bounds the blob size rendered in process; larger blobs
// make their commit fall back to git (which applies core.bigFileThreshold).
const nativeSynthMaxBlob = 64 << 20

// nativeSynthBinaryProbe mirrors git's FIRST_FEW_BYTES binary probe.
const nativeSynthBinaryProbe = 8000

// nativeSynthDisabled is the escape hatch for the in-process renderer.
func nativeSynthDisabled() bool {
	v := os.Getenv("PLENO_DLP_GIT_PATCH_RENDER")
	return v == "git" || v == "0"
}

func (s *Source) nativeSynthEligible() bool {
	return !s.promisorFiltered && !nativeSynthDisabled() && !s.nativeSynthCostly
}

// nativeSynthMaxCommits is the largest history the in-process renderer
// takes by default. It wins where per-process and pipe overhead dominates
// (croc, 2.4k commits: 0.28 s / 3.1 CPU-s against 0.32 s / 4.0 for
// `git log -p`), but on long histories the work is blob reconstruction
// and diffing, which git's C does with less CPU than Go while every shard
// already runs in parallel (django, 52k commits: 2.8 s / 47 CPU-s against
// 2.4 s / 43; #978). Unsharded histories are too small to repay its
// helper processes. PLENO_DLP_GIT_PATCH_RENDER=inprocess overrides both.
const nativeSynthMaxCommits = 20000

// chooseNativeSynth applies the cost rule to a walk of commits rendered by
// shards parallel workers.
func (s *Source) chooseNativeSynth(commits, shards int) {
	s.nativeSynthCostly = (shards <= 1 || commits > nativeSynthMaxCommits) &&
		os.Getenv("PLENO_DLP_GIT_PATCH_RENDER") != "inprocess"
}

// nativeRawArgs turns patch-rendering log arguments into the equivalent
// raw-only invocation.
func nativeRawArgs(patchArgs []string) []string {
	out := make([]string, 0, len(patchArgs))
	for _, a := range patchArgs {
		// These options only shape patch text, and several (-U,
		// --inter-hunk-context) imply --patch on their own.
		switch {
		case a == "--patch", a == "--no-indent-heuristic",
			strings.HasPrefix(a, "--unified="), strings.HasPrefix(a, "--inter-hunk-context="),
			strings.HasPrefix(a, "--diff-algorithm="), strings.HasPrefix(a, "--src-prefix="),
			strings.HasPrefix(a, "--dst-prefix="):
			continue
		}
		out = append(out, a)
	}
	return out
}

// nativeSynthRes are the long-lived helper processes one renderer uses.
type nativeSynthRes struct {
	blobs *catFileBatch // nil when odb reads blobs in process
	odb   *objectDB
	attrs *checkAttrBatch
}

func startNativeSynthRes(ctx context.Context, gitBin, repoAbs string, odb *objectDB) (*nativeSynthRes, error) {
	res := &nativeSynthRes{odb: odb}
	if odb == nil {
		blobs, err := startCatFileBatchArgs(ctx, gitBin, repoAbs, "--batch-command", "--buffer")
		if err != nil {
			return nil, err
		}
		res.blobs = blobs
	}
	attrs, err := startCheckAttrBatch(ctx, gitBin, repoAbs)
	if err != nil {
		res.close()
		return nil, err
	}
	res.attrs = attrs
	return res, nil
}

func (r *nativeSynthRes) close() {
	if r == nil {
		return
	}
	if r.blobs != nil {
		_ = r.blobs.close()
	}
	if r.attrs != nil {
		_ = r.attrs.close()
	}
}

// nativeObjectDBCache bounds the walk's shared delta-base cache.
const nativeObjectDBCache = 512 << 20

// objectDB opens the walk's in-process object reader once; nil means blobs
// are read through git cat-file instead.
func (s *Source) objectDB(ctx context.Context, gitBin string) *objectDB {
	s.odbOnce.Do(func() {
		if os.Getenv("PLENO_DLP_GIT_OBJECT_READER") == "git" {
			return
		}
		out, err := exec.CommandContext(ctx, gitBin, "-C", s.repoAbs, "rev-parse", "--path-format=absolute", "--git-path", "objects").Output()
		if err != nil {
			return
		}
		cacheBytes := int64(nativeObjectDBCache)
		if v, err := strconv.ParseInt(os.Getenv("PLENO_DLP_ODB_CACHE_MB"), 10, 64); err == nil {
			cacheBytes = v << 20
		}
		db, err := openObjectDB(strings.TrimSpace(string(out)), cacheBytes)
		if err != nil {
			return
		}
		s.odb = db
	})
	return s.odb
}

// diffAttrCache memoizes the "diff" attribute by path across the shards of
// one walk; attributes depend only on the path for the whole walk.
type diffAttrCache struct {
	mu      sync.Mutex
	m       map[string]string
	drivers map[string]int // driver name -> configured binary (-1 unset, 0, 1)
}

func (c *diffAttrCache) get(path string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[path]
	return v, ok
}

func (c *diffAttrCache) put(path, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]string)
	}
	if len(c.m) < binaryBlobCacheLimit {
		c.m[path] = v
	}
}

// nativeSynthLog renders one raw `git log` stream into patch text.
type nativeSynthLog struct {
	ctx       context.Context
	source    *Source
	gitBin    string
	patchArgs []string
	pathspec  string // the "--\n<paths>" stdin tail of a path-split item
	res       *nativeSynthRes
	out       *bufio.Writer
	xd        xdiffer

	commit  string
	head    []byte // commit header and raw lines, verbatim
	entries []nativeRawEntry
	patch   []byte
	bufA    []byte
	bufB    []byte
	// pending lists the blob responses requested but not yet read.
	pending []string
}

type nativeRawEntry struct {
	oldMode, newMode string
	oldOID, newOID   string
	status           byte
	token            string // path as git printed it (possibly C-quoted)
	path             string
}

var nativeZeroOID = strings.Repeat("0", 40)

var errNativeSynthFallback = errors.New("native patch render needs git")

func (r *nativeSynthLog) run(raw io.Reader) error {
	reader := bufio.NewReaderSize(raw, 256<<10)
	for {
		line, truncated, err := readNativeLine(reader, int(maxBlobSize)+1)
		if truncated {
			return fmt.Errorf("native raw line exceeds %d-byte limit", maxBlobSize)
		}
		if len(line) > 0 {
			if line[0] == nativeRecordSeparator {
				if err := r.finishCommit(); err != nil {
					return err
				}
				r.commit = nativeHeaderHash(line)
			} else if line[0] == ':' {
				entry, perr := parseNativeRawEntry(line)
				if perr != nil {
					return perr
				}
				r.entries = append(r.entries, entry)
			}
			r.head = append(r.head, line...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if err := r.ctx.Err(); err != nil {
			return err
		}
	}
	if err := r.finishCommit(); err != nil {
		return err
	}
	return r.out.Flush()
}

func nativeHeaderHash(line []byte) string {
	line = line[1:]
	if i := bytes.IndexByte(line, nativeFieldSeparator); i >= 0 {
		line = line[:i]
	}
	return string(line)
}

func parseNativeRawEntry(line []byte) (nativeRawEntry, error) {
	tab := bytes.IndexByte(line, '\t')
	if tab < 0 {
		return nativeRawEntry{}, fmt.Errorf("malformed native raw diff record %q", strings.TrimSpace(string(line)))
	}
	fields := strings.Fields(string(line[1:tab]))
	if len(fields) != 5 || len(fields[4]) == 0 {
		return nativeRawEntry{}, fmt.Errorf("malformed native raw diff record %q", strings.TrimSpace(string(line)))
	}
	token := string(bytes.TrimRight(line[tab+1:], "\r\n"))
	path, _, err := parseNativeRawPath(line)
	if err != nil {
		return nativeRawEntry{}, err
	}
	return nativeRawEntry{
		oldMode: fields[0], newMode: fields[1],
		oldOID: fields[2], newOID: fields[3],
		status: fields[4][0], token: token, path: path,
	}, nil
}

func (r *nativeSynthLog) finishCommit() error {
	if len(r.head) == 0 {
		return nil
	}
	defer func() {
		r.head = r.head[:0]
		r.entries = r.entries[:0]
		r.patch = r.patch[:0]
		r.commit = ""
	}()
	if len(r.entries) == 0 {
		_, err := r.out.Write(r.head)
		return err
	}
	r.patch = append(r.patch[:0], '\n')
	err := r.renderEntries()
	if errors.Is(err, errNativeSynthFallback) {
		if err := r.drainPending(); err != nil {
			return err
		}
		return r.renderWithGit()
	}
	if err != nil {
		return err
	}
	if _, err := r.out.Write(r.head); err != nil {
		return err
	}
	_, err = r.out.Write(r.patch)
	return err
}

// nativeSynthWindow bounds how many raw entries are prefetched per
// pipelined request (pipe buffers stay far below 64 KiB of requests).
const nativeSynthWindow = 256

func (r *nativeSynthLog) renderEntries() error {
	for i := range r.entries {
		if i%nativeSynthWindow == 0 {
			if err := r.prefetch(r.entries[i:min(i+nativeSynthWindow, len(r.entries))]); err != nil {
				return err
			}
		}
		e := &r.entries[i]
		if e.oldMode == "160000" || e.newMode == "160000" {
			return errNativeSynthFallback
		}
		switch e.status {
		case 'A', 'M', 'D':
			if err := r.renderPair(e, e.oldMode, e.newMode, e.oldOID, e.newOID); err != nil {
				return err
			}
		case 'T':
			// git splits a type change into a deletion and an addition.
			if err := r.renderPair(e, e.oldMode, "000000", e.oldOID, nativeZeroOID); err != nil {
				return err
			}
			if err := r.renderPair(e, "000000", e.newMode, nativeZeroOID, e.newOID); err != nil {
				return err
			}
		default:
			return errNativeSynthFallback
		}
	}
	return nil
}

func nativeQuotedName(prefix, token string) string {
	if strings.HasPrefix(token, "\"") {
		return "\"" + prefix + token[1:]
	}
	return prefix + token
}

func (r *nativeSynthLog) renderPair(e *nativeRawEntry, oldMode, newMode, oldOID, newOID string) error {
	oldValid, newValid := oldOID != nativeZeroOID, newOID != nativeZeroOID
	qa, qb := nativeQuotedName("a/", e.token), nativeQuotedName("b/", e.token)
	p := r.patch
	p = append(p, "diff --git "...)
	p = append(p, qa...)
	p = append(p, ' ')
	p = append(p, qb...)
	p = append(p, '\n')
	switch {
	case !oldValid:
		p = append(p, "new file mode "...)
		p = append(p, newMode...)
		p = append(p, '\n')
	case !newValid:
		p = append(p, "deleted file mode "...)
		p = append(p, oldMode...)
		p = append(p, '\n')
	case oldMode != newMode:
		p = append(p, "old mode "...)
		p = append(p, oldMode...)
		p = append(p, "\nnew mode "...)
		p = append(p, newMode...)
		p = append(p, '\n')
	}
	if oldOID == newOID {
		r.patch = p
		return nil
	}
	p = append(p, "index "...)
	p = append(p, oldOID...)
	p = append(p, ".."...)
	p = append(p, newOID...)
	if oldValid && newValid && oldMode == newMode {
		p = append(p, ' ')
		p = append(p, oldMode...)
	}
	p = append(p, '\n')
	r.patch = p

	attr, err := r.diffAttr(e.path)
	if err != nil {
		return err
	}
	var a, b []byte
	if oldValid {
		if r.bufA, err = r.readBlob(oldOID, r.bufA); err != nil {
			return err
		}
		a = r.bufA
	}
	if newValid {
		if r.bufB, err = r.readBlob(newOID, r.bufB); err != nil {
			return err
		}
		b = r.bufB
		r.source.binaryBlobs.store(newOID, bytes.IndexByte(b, 0) >= 0)
	}
	labelA, labelB := "/dev/null", "/dev/null"
	if oldValid {
		labelA = qa
	}
	if newValid {
		labelB = qb
	}
	binary := false
	switch attr {
	case "set":
	case "unset":
		binary = true
	default:
		binary = nativeProbeBinary(a) || nativeProbeBinary(b)
	}
	if binary {
		r.patch = fmt.Appendf(r.patch, "Binary files %s and %s differ\n", labelA, labelB)
		return nil
	}
	tabA, tabB := "", ""
	if strings.Contains(e.path, " ") {
		if oldValid {
			tabA = "\t"
		}
		if newValid {
			tabB = "\t"
		}
	}
	mark := len(r.patch)
	r.patch = fmt.Appendf(r.patch, "--- %s%s\n+++ %s%s\n", labelA, tabA, labelB, tabB)
	var any bool
	r.patch, any = r.xd.unified(r.patch, a, b)
	if !any {
		r.patch = r.patch[:mark]
	}
	return nil
}

func nativeProbeBinary(data []byte) bool {
	if len(data) > nativeSynthBinaryProbe {
		data = data[:nativeSynthBinaryProbe]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// diffAttr returns the effective "diff" attribute class for path: "set"
// (always text), "unset" (always binary), or "" (auto-detect). A named
// driver with a configured binary setting forces a git fallback.
func (r *nativeSynthLog) diffAttr(path string) (string, error) {
	cache := r.source.diffAttrs
	v, ok := cache.get(path)
	if !ok {
		var err error
		v, err = r.res.attrs.lookup(r.ctx, path)
		if err != nil {
			return "", err
		}
		cache.put(path, v)
	}
	switch v {
	case "set", "unset":
		return v, nil
	case "unspecified":
		return "", nil
	}
	binary, err := r.driverBinary(v)
	if err != nil {
		return "", err
	}
	if binary >= 0 {
		return "", errNativeSynthFallback
	}
	return "", nil
}

func (r *nativeSynthLog) driverBinary(name string) (int, error) {
	cache := r.source.diffAttrs
	cache.mu.Lock()
	v, ok := cache.drivers[name]
	cache.mu.Unlock()
	if ok {
		return v, nil
	}
	cmd := exec.CommandContext(r.ctx, r.gitBin, "-C", r.source.repoAbs, "config", "--get", "diff."+name+".binary")
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	v = -1
	if err == nil {
		v = 1
		if b, perr := strconv.ParseBool(strings.TrimSpace(string(out))); perr == nil && !b {
			v = 0
		}
	} else if ee, isExit := err.(*exec.ExitError); !isExit || ee.ExitCode() != 1 {
		if ctxErr := r.ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		// Unreadable configuration: let git decide.
		v = 1
	}
	cache.mu.Lock()
	if cache.drivers == nil {
		cache.drivers = make(map[string]int)
	}
	cache.drivers[name] = v
	cache.mu.Unlock()
	return v, nil
}

// prefetch resolves the window's uncached attributes and reads its blobs
// with one pipelined request each, instead of a pipe round trip per object.
func (r *nativeSynthLog) prefetch(window []nativeRawEntry) error {
	var paths []string
	seen := map[string]bool{}
	for _, e := range window {
		if _, ok := r.source.diffAttrs.get(e.path); !ok && !seen[e.path] {
			seen[e.path] = true
			paths = append(paths, e.path)
		}
	}
	if len(paths) > 0 {
		values, err := r.res.attrs.lookupMany(r.ctx, paths)
		if err != nil {
			return err
		}
		for i, p := range paths {
			r.source.diffAttrs.put(p, values[i])
		}
	}
	if r.res.blobs == nil {
		return nil
	}
	if r.res.blobs.broken != nil {
		return r.res.blobs.broken
	}
	var req []byte
	request := func(oid string) {
		req = append(req, "contents "...)
		req = append(req, oid...)
		req = append(req, '\n')
		r.pending = append(r.pending, oid)
	}
	for _, e := range window {
		if e.oldMode == "160000" || e.newMode == "160000" || e.oldOID == e.newOID {
			continue
		}
		switch e.status {
		case 'A', 'M', 'D', 'T':
		default:
			continue
		}
		if e.oldOID != nativeZeroOID {
			request(e.oldOID)
		}
		if e.newOID != nativeZeroOID {
			request(e.newOID)
		}
	}
	if len(req) == 0 {
		return nil
	}
	req = append(req, "flush\n"...)
	if _, err := r.res.blobs.stdin.Write(req); err != nil {
		return r.res.blobs.fail(fmt.Errorf("git: cat-file batch write: %w", err))
	}
	return nil
}

// drainPending consumes responses of a window abandoned for a fallback.
func (r *nativeSynthLog) drainPending() error {
	for len(r.pending) > 0 {
		if _, err := r.readBlob(r.pending[0], r.bufA); err != nil && !errors.Is(err, errNativeSynthFallback) {
			return err
		}
	}
	return nil
}

// readBlob reads the next pipelined response, which must be oid.
func (r *nativeSynthLog) readBlob(oid string, buf []byte) ([]byte, error) {
	if r.res.blobs == nil {
		data, err := r.res.odb.readBlob(oid, nativeSynthMaxBlob, buf)
		if err != nil {
			if ctxErr := r.ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, errNativeSynthFallback
		}
		return data, nil
	}
	if len(r.pending) == 0 || r.pending[0] != oid {
		return nil, fmt.Errorf("git: native patch render requested %s out of order", oid)
	}
	r.pending = r.pending[1:]
	data, err := r.res.blobs.readBlobResponse(r.ctx, oid, nativeSynthMaxBlob, buf)
	if err == nil {
		return data, nil
	}
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if r.res.blobs.broken != nil {
		return nil, err
	}
	// Missing, oversized, or non-blob objects: git reports them its own way.
	return nil, errNativeSynthFallback
}

// renderWithGit replaces the commit's synthesized output with git's own
// rendering of exactly that commit.
func (r *nativeSynthLog) renderWithGit() error {
	args := make([]string, 0, len(r.patchArgs)+1)
	for _, a := range r.patchArgs {
		switch {
		case a == "--reverse", a == "--topo-order", a == "--full-history",
			strings.HasPrefix(a, "--max-count="), strings.HasPrefix(a, "--since-as-filter="),
			a == "--no-walk=unsorted":
			continue
		case a == "--stdin":
			args = append(args, "--no-walk=unsorted")
		}
		args = append(args, a)
	}
	cmd := exec.CommandContext(r.ctx, r.gitBin, args...)
	cmd.Stdin = strings.NewReader(r.commit + "\n" + r.pathspec)
	cmd.Env = nativeGitEnv()
	var stderr limitedWriter
	stderr.limit = nativeStderrLimit
	cmd.Stderr = &stderr
	cmd.Stdout = r.out
	if err := cmd.Run(); err != nil {
		if ctxErr := r.ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("git: native log fallback for %s: %w: %s", r.commit, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// readBlobResponse reads one --batch-command "contents" response.
func (b *catFileBatch) readBlobResponse(ctx context.Context, oid string, limit int64, buf []byte) ([]byte, error) {
	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, b.fail(fmt.Errorf("git: cat-file batch header: %w", err))
	}
	fields := strings.Fields(header)
	if len(fields) == 2 && (fields[1] == "missing" || fields[1] == "ambiguous") {
		return nil, fmt.Errorf("git: %s: %w", oid, errCatFileMissing)
	}
	if len(fields) != 3 {
		return nil, b.fail(fmt.Errorf("git: cat-file batch malformed header %q", strings.TrimSpace(header)))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, b.fail(fmt.Errorf("git: cat-file batch malformed size in %q", strings.TrimSpace(header)))
	}
	if size > limit || fields[1] != "blob" {
		if _, err := b.stdout.Discard(int(size)); err != nil {
			return nil, b.fail(fmt.Errorf("git: cat-file batch body: %w", err))
		}
		if c, err := b.stdout.ReadByte(); err != nil || c != '\n' {
			return nil, b.fail(errors.New("git: cat-file batch missing record terminator"))
		}
		if fields[1] != "blob" {
			return nil, fmt.Errorf("git: %s is a %s, not a blob", oid, fields[1])
		}
		return nil, fmt.Errorf("git: blob %s exceeds %d bytes", oid, limit)
	}
	if int64(cap(buf)) < size {
		buf = make([]byte, size)
	}
	buf = buf[:size]
	if _, err := io.ReadFull(b.stdout, buf); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, b.fail(ctxErr)
		}
		return nil, b.fail(fmt.Errorf("git: cat-file batch body: %w", err))
	}
	if c, err := b.stdout.ReadByte(); err != nil || c != '\n' {
		return nil, b.fail(errors.New("git: cat-file batch missing record terminator"))
	}
	return buf, nil
}

// checkAttrBatch is one long-lived `git check-attr --stdin -z diff`.
type checkAttrBatch struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr limitedWriter
	broken error
}

func startCheckAttrBatch(ctx context.Context, gitBin, repoAbs string) (*checkAttrBatch, error) {
	b := &checkAttrBatch{}
	b.stderr.limit = nativeStderrLimit
	b.cmd = exec.CommandContext(ctx, gitBin, "-C", repoAbs, "check-attr", "--stdin", "-z", "diff")
	b.cmd.Env = nativeGitEnv()
	b.cmd.Stderr = &b.stderr
	stdin, err := b.cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: check-attr stdin: %w", err)
	}
	stdout, err := b.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: check-attr stdout: %w", err)
	}
	if err := b.cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start check-attr: %w", err)
	}
	b.stdin = stdin
	b.stdout = bufio.NewReaderSize(stdout, 16<<10)
	return b, nil
}

func (b *checkAttrBatch) lookup(ctx context.Context, path string) (string, error) {
	if b.broken != nil {
		return "", b.broken
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("git: check-attr cannot address %q", path)
	}
	if _, err := io.WriteString(b.stdin, path+"\x00"); err != nil {
		return "", b.fail(fmt.Errorf("git: check-attr write: %w", err))
	}
	return b.readOne(ctx)
}

func (b *checkAttrBatch) readOne(ctx context.Context) (string, error) {
	var fields [3]string
	for i := range fields {
		f, err := b.stdout.ReadString(0)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", b.fail(ctxErr)
			}
			return "", b.fail(fmt.Errorf("git: check-attr read: %w", err))
		}
		fields[i] = strings.TrimSuffix(f, "\x00")
	}
	if fields[1] != "diff" {
		return "", b.fail(fmt.Errorf("git: check-attr unexpected attribute %q", fields[1]))
	}
	return fields[2], nil
}

// lookupMany pipelines the lookups in bounded requests.
func (b *checkAttrBatch) lookupMany(ctx context.Context, paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for start := 0; start < len(paths); {
		var req []byte
		end := start
		for end < len(paths) && (end == start || len(req)+len(paths[end]) < 32<<10) {
			if strings.IndexByte(paths[end], 0) >= 0 {
				return nil, fmt.Errorf("git: check-attr cannot address %q", paths[end])
			}
			req = append(req, paths[end]...)
			req = append(req, 0)
			end++
		}
		if b.broken != nil {
			return nil, b.broken
		}
		if _, err := b.stdin.Write(req); err != nil {
			return nil, b.fail(fmt.Errorf("git: check-attr write: %w", err))
		}
		for i := start; i < end; i++ {
			v, err := b.readOne(ctx)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		start = end
	}
	return out, nil
}

func (b *checkAttrBatch) fail(err error) error {
	if detail := strings.TrimSpace(b.stderr.String()); detail != "" {
		err = fmt.Errorf("%w: %s", err, detail)
	}
	b.broken = err
	return err
}

func (b *checkAttrBatch) close() error {
	if b == nil || b.cmd == nil {
		return nil
	}
	_ = b.stdin.Close()
	if b.broken != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	err := b.cmd.Wait()
	b.cmd = nil
	if b.broken != nil {
		return nil
	}
	return err
}

// nativeRender runs a nativeSynthLog over a synth proc's raw stdout and
// exposes the rendered patch stream.
type nativeRender struct {
	out  *io.PipeReader
	done chan struct{}
	own  *nativeSynthRes
}

var errNativeRenderStopped = errors.New("native patch render stopped")

func (s *Source) startNativeRender(ctx context.Context, gitBin string, proc *nativeLogProc, res *nativeSynthRes) (*nativeRender, error) {
	render := &nativeRender{done: make(chan struct{})}
	if res == nil {
		var err error
		res, err = startNativeSynthRes(ctx, gitBin, s.repoAbs, s.objectDB(ctx, gitBin))
		if err != nil {
			return nil, err
		}
		render.own = res
	}
	pr, pw := io.Pipe()
	render.out = pr
	synth := &nativeSynthLog{
		ctx:       ctx,
		source:    s,
		gitBin:    gitBin,
		patchArgs: proc.patchArgs,
		pathspec:  proc.pathspec,
		res:       res,
		out:       bufio.NewWriterSize(pw, 256<<10),
	}
	raw := proc.stdout
	go func() {
		defer close(render.done)
		err := synth.run(raw)
		if err != nil {
			// Drain so git can exit instead of blocking on a full pipe.
			_, _ = io.Copy(io.Discard, raw)
		}
		_ = pw.CloseWithError(err)
	}()
	return render, nil
}

// stop unblocks and reaps the render goroutine once the parser is done.
func (r *nativeRender) stop() {
	_ = r.out.CloseWithError(errNativeRenderStopped)
	<-r.done
	r.own.close()
}
