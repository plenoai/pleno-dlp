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
	"time"
)

// In-process raw history (#1033).
//
// The newest-first stream used one `git log --raw` per segment only for
// the commit header and the recursive tree diff; git spends ~3 CPU-s on
// rails formatting what the renderer immediately re-parses. nativeRawGen
// reads commits and trees from the walk's shared object store and writes
// the same records git would: the header line of nativePrettyFormat and one
// ":<modes> <ids> <status>\t<path>" line per changed path, in git's tree
// order, for the stream's fixed options (--root -r --no-renames
// --diff-filter=d --diff-merges=off --ignore-submodules=all). Anything the
// generator does not model exactly — a commit or tree outside the packs, a
// submodule entry, a non-UTF-8 commit encoding, an unparsable identity —
// sends that commit to git instead, so the record set never changes.

// errNativeTreeFallback marks a commit the generator leaves to git.
var errNativeTreeFallback = errors.New("native raw record needs git")

// nativeTreeCache is each generator's private delta-base cache: trees are
// read far ahead of the renderers and must not evict their blob bases.
const nativeTreeCache = 128 << 20

// nativeTreeMaxObject bounds one commit or tree read in process.
const nativeTreeMaxObject = 64 << 20

// nativeTreeDiffEligible reports whether the repository's history can be
// listed in process: git would rewrite it through replace refs, grafts, or
// a shallow boundary, or format it under a non-default quoting or output
// encoding. Trufflehog mode asks git for rename detection and keeps git.
func (s *Source) nativeTreeDiffEligible(ctx context.Context, gitBin string) bool {
	if s.trufflehogCompatible || os.Getenv("PLENO_DLP_GIT_TREE_DIFF") == "git" {
		return false
	}
	git := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, gitBin, append([]string{"-C", s.repoAbs}, args...)...)
		cmd.Env = nativeGitEnv()
		return cmd.Output()
	}
	out, err := git("rev-parse", "--path-format=absolute", "--git-path", "shallow", "--git-path", "info/grafts")
	if err != nil {
		return false
	}
	for _, p := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	out, err = git("for-each-ref", "--count=1", "--format=%(refname)", "refs/replace/")
	if err != nil || len(bytes.TrimSpace(out)) > 0 {
		return false
	}
	out, err = git("config", "--get-regexp", `^(core\.quotepath|i18n\.logoutputencoding|i18n\.commitencoding)$`)
	if err != nil {
		var exit *exec.ExitError
		// Exit status 1: none of the keys is set.
		return errors.As(err, &exit) && exit.ExitCode() == 1
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "core.quotepath":
			if b, err := strconv.ParseBool(value); err != nil || !b {
				return false
			}
		default:
			if !nativeIsUTF8(value) {
				return false
			}
		}
	}
	return true
}

func nativeIsUTF8(name string) bool {
	return strings.EqualFold(name, "utf-8") || strings.EqualFold(name, "utf8")
}

// nativeRawGen writes raw history records for a list of commits.
type nativeRawGen struct {
	ctx  context.Context
	odb  *objectDB
	git  *nativeDiffTree // git's rendering of fallback commits
	out  *bufio.Writer
	path []byte // current directory prefix while diffing trees
	// entries holds the raw lines of the current commit.
	entries   []byte
	fallbacks int
}

// run writes the records of commits, in order.
func (g *nativeRawGen) run(commits []string) error {
	for _, c := range commits {
		if err := g.ctx.Err(); err != nil {
			return err
		}
		err := g.commit(c)
		if errors.Is(err, errNativeTreeFallback) {
			g.fallbacks++
			err = g.git.render(c, g.out)
		}
		if err != nil {
			return err
		}
	}
	return g.out.Flush()
}

// nativeDiffTree is one `git diff-tree --stdin` started with the walk's
// other helpers: a fallback mid-walk must not fork the then-large process
// (a fork per merge commit cost django ~100 system CPU-s). For a non-merge
// commit diff-tree prints exactly the record `git log --no-walk` prints
// with the same options, and it echoes a non-commit line, which delimits
// each response.
type nativeDiffTree struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr limitedWriter
	broken error
}

const nativeDiffTreeSentinel = "pleno-dlp-raw-end"

func startNativeDiffTree(ctx context.Context, gitBin, repoAbs string) (*nativeDiffTree, error) {
	d := &nativeDiffTree{}
	d.stderr.limit = nativeStderrLimit
	d.cmd = exec.CommandContext(ctx, gitBin, "-C", repoAbs, "diff-tree", "--stdin", "--root", "-r",
		"--raw", "--no-show-signature", "--abbrev=40", "--no-color", "--no-ext-diff", "--no-textconv",
		"--ignore-submodules=all", "--no-renames", "--diff-filter=d", "--format="+nativePrettyFormat)
	d.cmd.Env = nativeGitEnv()
	d.cmd.Stderr = &d.stderr
	var err error
	if d.stdin, err = d.cmd.StdinPipe(); err != nil {
		return nil, fmt.Errorf("git: diff-tree stdin: %w", err)
	}
	stdout, err := d.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: diff-tree stdout: %w", err)
	}
	if err := d.cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start diff-tree: %w", err)
	}
	d.stdout = bufio.NewReaderSize(stdout, 64<<10)
	return d, nil
}

// render copies git's record for commit to out.
func (d *nativeDiffTree) render(commit string, out io.Writer) error {
	if d.broken != nil {
		return d.broken
	}
	if _, err := io.WriteString(d.stdin, commit+"\n"+nativeDiffTreeSentinel+"\n"); err != nil {
		return d.fail(fmt.Errorf("git: diff-tree write: %w", err))
	}
	for {
		line, truncated, err := readNativeLine(d.stdout, int(maxBlobSize)+1)
		if truncated {
			return d.fail(fmt.Errorf("git: diff-tree line exceeds %d-byte limit", maxBlobSize))
		}
		if string(line) == nativeDiffTreeSentinel+"\n" {
			return nil
		}
		if len(line) > 0 {
			if _, werr := out.Write(line); werr != nil {
				return werr
			}
		}
		if err != nil {
			return d.fail(fmt.Errorf("git: diff-tree read: %w", err))
		}
	}
}

func (d *nativeDiffTree) fail(err error) error {
	if detail := strings.TrimSpace(d.stderr.String()); detail != "" {
		err = fmt.Errorf("%w: %s", err, detail)
	}
	d.broken = err
	return err
}

func (d *nativeDiffTree) close() {
	if d == nil {
		return
	}
	_ = d.stdin.Close()
	if d.broken != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}
	_ = d.cmd.Wait()
}

// commit writes one commit's record, or returns errNativeTreeFallback
// before writing anything.
func (g *nativeRawGen) commit(hash string) error {
	var id [20]byte
	if len(hash) != 40 {
		return errNativeTreeFallback
	}
	if _, err := hex.Decode(id[:], []byte(hash)); err != nil {
		return errNativeTreeFallback
	}
	ref, err := g.odb.readRef(id[:], odbObjCommit, nativeTreeMaxObject)
	if err != nil {
		return errNativeTreeFallback
	}
	defer ref.release(g.odb)
	c, ok := parseNativeRawCommit(ref.data)
	if !ok {
		return errNativeTreeFallback
	}
	if len(c.parents) > 1 {
		// --diff-merges=off with --diff-filter: git lists no merge.
		return nil
	}
	g.entries = g.entries[:0]
	var oldTree []byte
	if len(c.parents) == 1 {
		parent, err := g.odb.readRef(c.parents[0], odbObjCommit, nativeTreeMaxObject)
		if err != nil {
			return errNativeTreeFallback
		}
		pc, ok := parseNativeRawCommit(parent.data)
		oldTree = pc.tree
		parent.release(g.odb)
		if !ok {
			return errNativeTreeFallback
		}
	}
	if !bytes.Equal(oldTree, c.tree) {
		g.path = g.path[:0]
		if err := g.diffTrees(oldTree, c.tree); err != nil {
			return err
		}
	}
	if len(g.entries) == 0 {
		// --diff-filter limits the walk: git omits a commit with no
		// selected change (an empty or deletion-only commit).
		return nil
	}
	w := g.out
	w.WriteByte(nativeRecordSeparator)
	w.WriteString(hash)
	w.WriteByte(nativeFieldSeparator)
	for i, p := range c.parents {
		if i > 0 {
			w.WriteByte(' ')
		}
		var buf [40]byte
		hex.Encode(buf[:], p)
		w.Write(buf[:])
	}
	w.WriteByte(nativeFieldSeparator)
	w.Write(c.name)
	w.WriteByte(nativeFieldSeparator)
	w.Write(c.email)
	w.WriteByte(nativeFieldSeparator)
	w.WriteString(c.date)
	w.WriteByte(nativeFieldSeparator)
	w.Write(c.subject)
	w.WriteByte(nativeFieldSeparator)
	w.WriteString("\n\n")
	w.Write(g.entries)
	return nil
}

type nativeRawCommit struct {
	tree    []byte   // raw id; nil for a malformed commit
	parents [][]byte // raw ids
	name    []byte
	email   []byte
	date    string // %aI
	subject []byte // %s
}

// parseNativeRawCommit decodes what nativePrettyFormat prints from a commit
// object; ok is false wherever git's formatting is not reproduced exactly.
func parseNativeRawCommit(data []byte) (c nativeRawCommit, ok bool) {
	if bytes.IndexByte(data, 0) >= 0 {
		// git formats the message as a C string.
		return c, false
	}
	header, msg, found := bytes.Cut(data, []byte("\n\n"))
	if !found {
		header, msg = bytes.TrimSuffix(data, []byte("\n")), nil
	}
	var author []byte
	haveAuthor := false
	for len(header) > 0 {
		line := header
		if i := bytes.IndexByte(header, '\n'); i >= 0 {
			line, header = header[:i], header[i+1:]
		} else {
			header = nil
		}
		key, value, _ := bytes.Cut(line, []byte(" "))
		switch string(key) {
		case "tree":
			if c.tree != nil || len(c.parents) > 0 || haveAuthor {
				return c, false
			}
			c.tree = nativeDecodeID(value)
			if c.tree == nil {
				return c, false
			}
		case "parent":
			id := nativeDecodeID(value)
			if id == nil || c.tree == nil || haveAuthor {
				return c, false
			}
			c.parents = append(c.parents, id)
		case "author":
			if !haveAuthor {
				author, haveAuthor = value, true
			}
		case "encoding":
			if !nativeIsUTF8(string(value)) {
				return c, false
			}
		}
	}
	if c.tree == nil || !haveAuthor {
		return c, false
	}
	if c.name, c.email, c.date, ok = nativeSplitIdent(author); !ok {
		return c, false
	}
	c.subject = nativeSubject(msg)
	return c, true
}

func nativeDecodeID(value []byte) []byte {
	if len(value) != 40 {
		return nil
	}
	id := make([]byte, 20)
	if _, err := hex.Decode(id, value); err != nil {
		return nil
	}
	return id
}

func nativeGitSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// nativeSplitIdent ports split_ident_line for %an, %ae, and %aI. Identities
// whose date git would print in another form are refused.
func nativeSplitIdent(line []byte) (name, email []byte, date string, ok bool) {
	lt := bytes.IndexByte(line, '<')
	if lt < 0 {
		return nil, nil, "", false
	}
	end := lt
	for end > 0 && nativeGitSpace(line[end-1]) {
		end--
	}
	name = line[:end]
	gt := bytes.IndexByte(line[lt+1:], '>')
	if gt < 0 {
		return nil, nil, "", false
	}
	email = line[lt+1 : lt+1+gt]
	rest := line[lt+1+gt+1:]
	if bytes.IndexByte(rest, '>') >= 0 {
		// git takes the date after the last '>'.
		return nil, nil, "", false
	}
	fields := bytes.Fields(rest)
	if len(fields) != 2 {
		return nil, nil, "", false
	}
	ts, err := strconv.ParseInt(string(fields[0]), 10, 64)
	if err != nil || ts < 0 || ts > 253402300799 || fields[0][0] == '+' {
		return nil, nil, "", false
	}
	tz := fields[1]
	if len(tz) != 5 || (tz[0] != '+' && tz[0] != '-') {
		return nil, nil, "", false
	}
	hh, err1 := strconv.Atoi(string(tz[1:3]))
	mm, err2 := strconv.Atoi(string(tz[3:5]))
	if err1 != nil || err2 != nil || mm >= 60 || hh >= 24 {
		return nil, nil, "", false
	}
	offset := hh*3600 + mm*60
	if tz[0] == '-' {
		offset = -offset
	}
	t := time.Unix(ts, 0).In(time.FixedZone("", offset))
	return name, email, t.Format("2006-01-02T15:04:05-07:00"), true
}

// nativeSubject ports format_subject: the first paragraph after leading
// blank lines, each line right-trimmed and joined by single spaces.
func nativeSubject(msg []byte) []byte {
	var out []byte
	started := false
	for len(msg) > 0 {
		line := msg
		if i := bytes.IndexByte(msg, '\n'); i >= 0 {
			line, msg = msg[:i], msg[i+1:]
		} else {
			msg = nil
		}
		for len(line) > 0 && nativeGitSpace(line[len(line)-1]) {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			if started {
				break
			}
			continue
		}
		if started {
			out = append(out, ' ')
		}
		out = append(out, line...)
		started = true
	}
	return out
}

// Tree entry modes, canonicalized as git's canon_mode does.
const (
	nativeModeTree    = 0o040000
	nativeModeFile    = 0o100644
	nativeModeExec    = 0o100755
	nativeModeLink    = 0o120000
	nativeModeGitlink = 0o160000
)

type nativeTreeEntry struct {
	mode uint32
	name []byte
	id   []byte
}

// nativeNextEntry decodes the tree entry at the start of data.
func nativeNextEntry(data []byte) (e nativeTreeEntry, rest []byte, ok bool) {
	sp := bytes.IndexByte(data, ' ')
	if sp <= 0 {
		return e, nil, false
	}
	var mode uint32
	for _, c := range data[:sp] {
		if c < '0' || c > '7' {
			return e, nil, false
		}
		mode = mode<<3 | uint32(c-'0')
	}
	nul := bytes.IndexByte(data[sp+1:], 0)
	if nul <= 0 || sp+1+nul+21 > len(data) {
		return e, nil, false
	}
	switch mode & 0o170000 {
	case 0o100000:
		if mode&0o100 != 0 {
			mode = nativeModeExec
		} else {
			mode = nativeModeFile
		}
	case 0o120000:
		mode = nativeModeLink
	case 0o040000:
		mode = nativeModeTree
	default:
		mode = nativeModeGitlink
	}
	e = nativeTreeEntry{mode: mode, name: data[sp+1 : sp+1+nul], id: data[sp+1+nul+1 : sp+1+nul+21]}
	return e, data[sp+1+nul+21:], true
}

// nativeEntryCompare ports base_name_compare: a tree sorts as if its name
// ended in '/'.
func nativeEntryCompare(a, b *nativeTreeEntry) int {
	n := min(len(a.name), len(b.name))
	if c := bytes.Compare(a.name[:n], b.name[:n]); c != 0 {
		return c
	}
	next := func(e *nativeTreeEntry) byte {
		if n < len(e.name) {
			return e.name[n]
		}
		if e.mode == nativeModeTree {
			return '/'
		}
		return 0
	}
	ca, cb := next(a), next(b)
	switch {
	case ca < cb:
		return -1
	case ca > cb:
		return 1
	}
	return 0
}

// readTree returns the tree object id; a nil id is the empty tree.
func (g *nativeRawGen) readTree(id []byte) (*odbBuf, []byte, error) {
	if id == nil {
		return nil, nil, nil
	}
	ref, err := g.odb.readRef(id, odbObjTree, nativeTreeMaxObject)
	if err != nil {
		return nil, nil, errNativeTreeFallback
	}
	return ref, ref.data, nil
}

// diffTrees appends the raw lines of old -> new under g.path.
func (g *nativeRawGen) diffTrees(oldID, newID []byte) error {
	oldRef, oldData, err := g.readTree(oldID)
	if err != nil {
		return err
	}
	if oldRef != nil {
		defer oldRef.release(g.odb)
	}
	newRef, newData, err := g.readTree(newID)
	if err != nil {
		return err
	}
	if newRef != nil {
		defer newRef.release(g.odb)
	}
	var a, b nativeTreeEntry
	haveA, haveB := false, false
	var ok bool
	for {
		if !haveA && len(oldData) > 0 {
			if a, oldData, ok = nativeNextEntry(oldData); !ok {
				return errNativeTreeFallback
			}
			haveA = true
		}
		if !haveB && len(newData) > 0 {
			if b, newData, ok = nativeNextEntry(newData); !ok {
				return errNativeTreeFallback
			}
			haveB = true
		}
		if !haveA && !haveB {
			return nil
		}
		cmp := 0
		switch {
		case !haveA:
			cmp = 1
		case !haveB:
			cmp = -1
		default:
			cmp = nativeEntryCompare(&a, &b)
		}
		switch {
		case cmp < 0:
			// Deleted: --diff-filter=d drops it (and a deleted tree's
			// contents); a submodule is ignored either way.
			haveA = false
		case cmp > 0:
			if err := g.added(&b); err != nil {
				return err
			}
			haveB = false
		default:
			haveA, haveB = false, false
			if a.mode == b.mode && bytes.Equal(a.id, b.id) {
				continue
			}
			if a.mode == nativeModeGitlink || b.mode == nativeModeGitlink {
				return errNativeTreeFallback
			}
			if a.mode == nativeModeTree {
				mark := len(g.path)
				g.path = append(append(g.path, a.name...), '/')
				err := g.diffTrees(a.id, b.id)
				g.path = g.path[:mark]
				if err != nil {
					return err
				}
				continue
			}
			status := byte('M')
			if a.mode&0o170000 != b.mode&0o170000 {
				status = 'T'
			}
			g.appendEntry(a.mode, b.mode, a.id, b.id, status, b.name)
		}
	}
}

// added appends an added entry, recursing into an added tree.
func (g *nativeRawGen) added(e *nativeTreeEntry) error {
	switch e.mode {
	case nativeModeGitlink:
		return errNativeTreeFallback
	case nativeModeTree:
		mark := len(g.path)
		g.path = append(append(g.path, e.name...), '/')
		err := g.diffTrees(nil, e.id)
		g.path = g.path[:mark]
		return err
	}
	g.appendEntry(0, e.mode, nil, e.id, 'A', e.name)
	return nil
}

var nativeZeroID = make([]byte, 20)

func (g *nativeRawGen) appendEntry(oldMode, newMode uint32, oldID, newID []byte, status byte, name []byte) {
	if oldID == nil {
		oldID = nativeZeroID
	}
	out := g.entries
	out = append(out, ':')
	out = nativeAppendMode(out, oldMode)
	out = append(out, ' ')
	out = nativeAppendMode(out, newMode)
	out = append(out, ' ')
	out = hex.AppendEncode(out, oldID)
	out = append(out, ' ')
	out = hex.AppendEncode(out, newID)
	out = append(out, ' ', status, '\t')
	mark := len(g.path)
	g.path = append(g.path, name...)
	out = nativeAppendQuoted(out, g.path)
	g.path = g.path[:mark]
	g.entries = append(out, '\n')
}

func nativeAppendMode(out []byte, mode uint32) []byte {
	return append(out,
		byte('0'+mode>>15&7), byte('0'+mode>>12&7), byte('0'+mode>>9&7),
		byte('0'+mode>>6&7), byte('0'+mode>>3&7), byte('0'+mode&7))
}

// nativeAppendQuoted ports quote_c_style with core.quotePath enabled.
func nativeAppendQuoted(out, path []byte) []byte {
	needs := false
	for _, c := range path {
		if c < 0x20 || c == '"' || c == '\\' || c >= 0x7f {
			needs = true
			break
		}
	}
	if !needs {
		return append(out, path...)
	}
	out = append(out, '"')
	for _, c := range path {
		switch c {
		case '\a':
			out = append(out, '\\', 'a')
		case '\b':
			out = append(out, '\\', 'b')
		case '\t':
			out = append(out, '\\', 't')
		case '\n':
			out = append(out, '\\', 'n')
		case '\v':
			out = append(out, '\\', 'v')
		case '\f':
			out = append(out, '\\', 'f')
		case '\r':
			out = append(out, '\\', 'r')
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			if c < 0x20 || c >= 0x7f {
				out = append(out, '\\', '0'+c>>6, '0'+c>>3&7, '0'+c&7)
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, '"')
}

// startNativeRawGen runs a generator for commits behind a pipe. Its
// diff-tree helper is started here, before the walk's heap grows.
func startNativeRawGen(ctx context.Context, odb *objectDB, gitBin, repoAbs string, commits []string) *nativeRawSource {
	helper, err := startNativeDiffTree(ctx, gitBin, repoAbs)
	if err != nil {
		return &nativeRawSource{err: err, kill: func() {}, wait: func() error { return nil }}
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		g := &nativeRawGen{ctx: ctx, odb: odb.view(nativeTreeCache), git: helper, out: bufio.NewWriterSize(pw, 256<<10)}
		err := g.run(commits)
		helper.close()
		_ = pw.CloseWithError(err)
		done <- err
	}()
	var stopped bool
	return &nativeRawSource{
		stdout: pr,
		kill: func() {
			_ = pr.CloseWithError(errNativeRenderStopped)
		},
		wait: func() error {
			if stopped {
				return nil
			}
			stopped = true
			_ = pr.CloseWithError(errNativeRenderStopped)
			err := <-done
			if errors.Is(err, errNativeRenderStopped) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		},
	}
}
