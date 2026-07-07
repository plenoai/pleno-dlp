// Package git walks local git history and emits added content per commit.
package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const binarySniffLen = 512

const maxBlobSize int64 = 50 * 1024 * 1024 // 50 MiB

// maxDiffBlobSize bounds the blob size (either side) that firstChangedLine
// and addedHunks will run a diff over. change.Patch() reads both blob sides
// fully into strings with no cap of its own — maxBlobSize above does not
// protect this path — and then hands them to a Myers diff that expands them
// roughly 4x further as []rune. A single large text blob (SQL dump,
// lockfile, generated code) can therefore spike memory by multiple GiB.
// Above this bound the diff is skipped entirely: firstChangedLine degrades
// to 0 (unknown) and addedHunks emits nothing for that change, rather than
// fall back to full-blob emission — the #264 memory/scan-bytes blowup this
// change exists to avoid reintroducing.
const maxDiffBlobSize int64 = 1 << 20 // 1 MiB

// diffContextLines is the number of unchanged lines kept on either side of
// an added hunk, mirroring `git diff -U3`. It only bounds context: a run of
// consecutively added lines (e.g. a pasted-in secret block) is a single
// diff.Add chunk and is always emitted in full regardless of length.
const diffContextLines = 3

func init() {
	sources.Register(sources.SourceGit, func() sources.Source { return &Source{} })
}

type Config struct {
	Repo     string   `json:"repo"`
	Branch   string   `json:"branch,omitempty"`
	MaxDepth int      `json:"max_depth,omitempty"`
	Since    string   `json:"since,omitempty"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
	// AllBranches walks every reachable commit on every ref (HEAD plus all
	// refs/heads/ and refs/remotes/), not just the single resolved start.
	// This is trufflehog-parity full-history mode. Off by default so the
	// existing single-branch contract is byte-identical.
	AllBranches bool `json:"all_branches,omitempty"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	concurrency int

	repoAbs     string
	branch      string
	allBranches bool
	maxDepth    int
	since       time.Time
	include     []string
	exclude     []string

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int    `json:"version"`
	Head    string `json:"head"`
	// Heads records the head hash of every start ref from the previous run
	// (multi-branch mode). Legacy single-branch state only populated Head;
	// readers must honour both. On rerun, the union of Head and Heads forms
	// the stop-set: any commit reachable from a previously recorded head
	// terminates that lineage so already-scanned history is not re-emitted.
	Heads []string `json:"heads,omitempty"`
}

func (s *Source) Type() sources.SourceType { return sources.SourceGit }

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, _ bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("git: invalid config json: %w", err)
		}
	}
	if cfg.Repo == "" {
		return errors.New("git: config.repo must be set to a local repository path")
	}
	abs, err := filepath.Abs(cfg.Repo)
	if err != nil {
		return fmt.Errorf("git: resolve repo path: %w", err)
	}
	if _, err := git.PlainOpen(abs); err != nil {
		return fmt.Errorf("git: open repo %q: %w", abs, err)
	}
	if cfg.Since != "" {
		t, err := time.Parse(time.RFC3339, cfg.Since)
		if err != nil {
			return fmt.Errorf("git: invalid since %q (want RFC3339): %w", cfg.Since, err)
		}
		s.since = t
	}
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, "x"); err != nil {
			return fmt.Errorf("git: bad glob %q: %w", p, err)
		}
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.concurrency = concurrency
	s.repoAbs = abs
	s.branch = cfg.Branch
	s.allBranches = cfg.AllBranches
	s.maxDepth = cfg.MaxDepth
	s.include = cfg.Include
	s.exclude = cfg.Exclude
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	repo, err := git.PlainOpen(s.repoAbs)
	if err != nil {
		return fmt.Errorf("git: reopen repo: %w", err)
	}
	starts, err := s.resolveStarts(repo)
	if err != nil {
		return err
	}
	s.nextState = newIncrementalState(starts)

	stops := s.previousHeads()
	refs, err := s.collectCommits(repo, starts, stops)
	if err != nil {
		return err
	}

	// refs holds only hash+timestamp (see collectCommits); re-fetch each
	// *object.Commit here rather than holding the whole history's commit
	// objects live at once. go-git's object storer caches recently decoded
	// objects, so this re-fetch is cheap for commits we just walked.
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, err := repo.CommitObject(r.hash)
		if err != nil {
			continue // pruned/rewritten between collect and emit — tolerate, don't abort
		}
		if err := s.emitCommit(ctx, c, ch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) SetIncrementalState(previous json.RawMessage) error {
	s.hasPreviousState = false
	s.previousState = nil
	s.nextState = nil
	if len(previous) == 0 || string(previous) == "null" {
		return nil
	}
	var state incrementalState
	if err := json.Unmarshal(previous, &state); err != nil {
		return err
	}
	s.hasPreviousState = true
	s.previousState = &state
	return nil
}

func (s *Source) IncrementalState() json.RawMessage {
	if s.nextState == nil {
		return nil
	}
	data, err := json.Marshal(s.nextState)
	if err != nil {
		return nil
	}
	return data
}

// ResourceFingerprint identifies the scanned git resource set.
func (s *Source) ResourceFingerprint(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	repo, err := git.PlainOpen(s.repoAbs)
	if err != nil {
		return "", fmt.Errorf("git: reopen repo: %w", err)
	}
	starts, err := s.resolveStarts(repo)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeHash(h, "git-v1")
	writeHash(h, s.repoAbs)
	// Sort start hashes so the fingerprint is independent of ref iteration
	// order. In single-start mode this is a one-element set and the digest is
	// byte-identical to the legacy output.
	hashStrs := make([]string, 0, len(starts))
	for _, sh := range starts {
		hashStrs = append(hashStrs, sh.String())
	}
	sort.Strings(hashStrs)
	for _, sh := range hashStrs {
		writeHash(h, sh)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolveStart picks the single commit hash to start the walk from. Retained
// for the single-branch contract: branch override, else HEAD.
func (s *Source) resolveStart(repo *git.Repository) (plumbing.Hash, error) {
	if s.branch != "" {
		ref, err := repo.Reference(plumbing.NewBranchReferenceName(s.branch), true)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("git: resolve branch %q: %w", s.branch, err)
		}
		return ref.Hash(), nil
	}
	head, err := repo.Head()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("git: HEAD: %w", err)
	}
	return head.Hash(), nil
}

// resolveStarts returns the ordered, de-duplicated set of commit hashes the
// walk begins from. With AllBranches=false (and no branch override) this is
// exactly [HEAD] — byte-identical to the legacy single-start behaviour. With
// AllBranches=true it is HEAD plus every ref under refs/heads/ and
// refs/remotes/, identical hashes collapsed. A branch override always pins to
// that one branch regardless of AllBranches.
func (s *Source) resolveStarts(repo *git.Repository) ([]plumbing.Hash, error) {
	if s.branch != "" || !s.allBranches {
		h, err := s.resolveStart(repo)
		if err != nil {
			return nil, err
		}
		return []plumbing.Hash{h}, nil
	}

	var starts []plumbing.Hash
	seen := map[plumbing.Hash]struct{}{}
	add := func(h plumbing.Hash) {
		if h == plumbing.ZeroHash {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		starts = append(starts, h)
	}

	// HEAD first (preserves "default branch leads" ordering when present).
	if head, err := repo.Head(); err == nil {
		add(head.Hash())
	}

	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("git: list references: %w", err)
	}
	defer refs.Close()
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() != plumbing.HashReference {
			return nil // skip symbolic refs
		}
		name := ref.Name().String()
		if !strings.HasPrefix(name, "refs/heads/") && !strings.HasPrefix(name, "refs/remotes/") {
			return nil
		}
		add(ref.Hash())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("git: iterate references: %w", err)
	}
	if len(starts) == 0 {
		return nil, errors.New("git: no branch heads to walk")
	}
	return starts, nil
}

// commitRef is the minimal record kept for a collected commit: enough to
// sort by time and re-fetch the full *object.Commit later. Holding only this
// (not the decoded commit, which carries message/author/tree references)
// keeps the pre-walk collection's memory proportional to commit count, not
// to full history size.
type commitRef struct {
	hash plumbing.Hash
	when time.Time
}

// collectCommits walks every lineage reachable from the start hashes and
// returns commitRefs for the union of commits in oldest-first order.
//
// Memory: only hash+timestamp is retained per commit (see commitRef); the
// caller re-fetches each *object.Commit from the repo (cheaply, via go-git's
// object cache) when it actually emits chunks for it.
//
// Traversal: seen is a single map shared across every start's walk AND used
// as the incremental stop-set seed. It is passed as the seenExternal
// argument to object.NewCommitPreorderIter — the same construct
// repo.Log's default order uses internally, just with cross-call sharing
// enabled. seenExternal is checked as an OR alongside the iterator's own
// internal seen set, and only ever suppresses returning that one already-
// seen commit; it does not push that commit's parents, but sibling
// branches already queued on the walk's stack are visited normally. So
// once a lineage merges into anything already visited (by a prior start's
// completed walk, or by the stop-set), that lineage's remaining ancestry is
// pruned instead of being re-walked and merely discarded — turning the
// previous O(starts × history) cost into O(total reachable commits).
// This is only correct because each start's walk runs to completion (or to
// the maxDepth cutoff) before the next start begins: by induction, any hash
// already in seen when a later start's walk reaches it was returned by a
// walk that has already visited that hash's own ancestors too, so pruning
// there loses nothing.
//
// seen is seeded from boundarySet(stops), which holds only the previous
// run's head hashes themselves, not their full ancestry (see boundarySet).
// This is sufficient: any commit the previous run scanned is an ancestor of
// one of those heads, and on append-only history every walk path from a
// current start down to that commit passes through the recorded head first
// — go-git's iterator prunes there (see boundarySet) before ever reaching
// the older commit, so its ancestry never needs to be enumerated up front.
func (s *Source) collectCommits(repo *git.Repository, starts []plumbing.Hash, stops []plumbing.Hash) ([]commitRef, error) {
	seen := boundarySet(stops)

	var refs []commitRef

	for _, start := range starts {
		if seen[start] {
			continue
		}
		startCommit, err := repo.CommitObject(start)
		if err != nil {
			return nil, fmt.Errorf("git: resolve start %s: %w", start, err)
		}
		iter := object.NewCommitPreorderIter(startCommit, seen, nil)
		err = iter.ForEach(func(c *object.Commit) error {
			// go-git's preorder ForEach aborts the WHOLE walk on any returned
			// error, so the only error we may return is the terminal maxDepth
			// stop.
			seen[c.Hash] = true
			if !s.since.IsZero() && c.Committer.When.Before(s.since) {
				return nil
			}
			refs = append(refs, commitRef{hash: c.Hash, when: c.Committer.When})
			if s.maxDepth > 0 && len(refs) >= s.maxDepth {
				return errStorerStop
			}
			return nil
		})
		iter.Close()
		if err != nil && !errors.Is(err, errStorerStop) {
			return nil, fmt.Errorf("git: iterate commits: %w", err)
		}
		if s.maxDepth > 0 && len(refs) >= s.maxDepth {
			break
		}
	}

	sort.SliceStable(refs, func(i, j int) bool {
		return refs[i].when.Before(refs[j].when)
	})
	return refs, nil
}

// boundarySet returns the given previous-run head hashes as a lookup set
// (deduplicated, ZeroHash dropped) for use as the seenExternal argument to
// object.NewCommitPreorderIter in collectCommits.
//
// This used to instead be reachableSet: a BFS that walked every commit's
// full ancestry back from each stop head and materialized the whole result
// into a map before the incremental walk even started — O(total previously
// scanned history) memory and time, GiB-scale on a million-commit repo
// (#270). It does not need to be: go-git's preorder iterator, given a
// hash in seenExternal, stops there and never pushes that commit's parents
// (see commitPreIterator.Next in go-git's commit_walker.go) — so the walk
// itself already halts a lineage the moment it reaches a previous head,
// without seenExternal needing to contain that head's ancestors too. So the
// boundary only needs the heads themselves: seeding seen with just those is
// enough for collectCommits' forward walk to stay within the previously
// scanned region, and it costs O(number of heads) instead of O(history).
//
// This is exactly as correct as the BFS it replaces on append-only history:
// a commit X scanned by the previous run is (by construction) an ancestor
// of one of these heads, and every path from a current start to X passes
// through that head first. If history was rewritten (rebase/force-push)
// such that a stop head is no longer an ancestor of any current start, both
// this version and the BFS it replaces degrade to scanning more than
// strictly necessary rather than missing anything — never an abort, and
// never a false "already scanned."
func boundarySet(roots []plumbing.Hash) map[plumbing.Hash]bool {
	set := make(map[plumbing.Hash]bool, len(roots))
	for _, r := range roots {
		if r == plumbing.ZeroHash {
			continue
		}
		set[r] = true
	}
	return set
}

var errStorerStop = errors.New("git: stop iteration")

// emitCommit diffs the commit against its first parent.
func (s *Source) emitCommit(ctx context.Context, c *object.Commit, ch chan<- *sources.Chunk) error {
	newTree, err := c.Tree()
	if err != nil {
		return nil // skip unreadable commits, never abort whole scan
	}

	var oldTree *object.Tree
	if c.NumParents() > 0 {
		parent, err := c.Parent(0)
		if err == nil {
			oldTree, _ = parent.Tree()
		}
	}

	changes, err := object.DiffTreeWithOptions(ctx, oldTree, newTree, &object.DiffTreeOptions{DetectRenames: false})
	if err != nil {
		return nil
	}

	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		from, to, err := change.Files()
		if err != nil || to == nil {
			// Pure deletions have no `to` file — there is nothing to scan.
			continue
		}
		path := change.To.Name
		if !s.pathAllowed(path) {
			continue
		}

		bin, err := to.IsBinary()
		if err == nil && bin {
			continue
		}
		// A from==nil change (file added, or the insert half of a rename
		// under DetectRenames:false above) has no prior version to diff
		// against — the whole file IS the new content, so full-blob
		// emission here is a one-time cost, not the repeated-rescan
		// blowup #264 targets. A genuine modification instead emits only
		// the added hunks (+ context): the full new blob would otherwise
		// be re-emitted on every commit that touches the file.
		var data []byte
		var ok bool
		if from == nil {
			data, ok = readBlob(to)
		} else {
			data, ok = addedHunks(change, from, to)
		}
		if !ok {
			continue
		}
		// Belt-and-suspenders: go-git's IsBinary uses sniff bytes, but a few
		// blob types (UTF-16 BOM-less) slip through. The NUL-byte test
		// matches what the filesystem source applies.
		if isBinary(data) {
			continue
		}

		line := firstChangedLine(change, from, to)
		commitMsg := c.Message
		if nl := strings.IndexByte(commitMsg, '\n'); nl >= 0 {
			commitMsg = commitMsg[:nl]
		}
		chunk := &sources.Chunk{
			SourceID:   s.sourceID,
			SourceType: sources.SourceGit,
			SourceName: s.name,
			Data:       data,
			SourceMetadata: sources.Metadata{
				Git: &sources.GitMeta{
					Repository:   s.repoAbs,
					Commit:       c.Hash.String(),
					File:         path,
					Line:         line,
					Email:        c.Author.Email,
					Author:       c.Author.Name,
					AuthoredDate: c.Author.When.UTC().Format(time.RFC3339),
					Message:      commitMsg,
				},
			},
		}
		select {
		case ch <- chunk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// pathAllowed applies include/exclude globs. Empty include = allow all;
// non-empty include requires a match. Exclude trumps include.
func (s *Source) pathAllowed(path string) bool {
	for _, pat := range s.exclude {
		if ok, _ := filepath.Match(pat, path); ok {
			return false
		}
	}
	if len(s.include) == 0 {
		return true
	}
	for _, pat := range s.include {
		if ok, _ := filepath.Match(pat, path); ok {
			return true
		}
	}
	return false
}

// readBlob returns up to maxBlobSize bytes of a blob. Returning ok=false on
// any read error means we skip the blob silently — partial-read corruption
// would only produce noisy false detector hits.
func readBlob(f *object.File) ([]byte, bool) {
	rdr, err := f.Reader()
	if err != nil {
		return nil, false
	}
	defer rdr.Close()
	data, err := io.ReadAll(io.LimitReader(rdr, maxBlobSize))
	if err != nil {
		return nil, false
	}
	return data, true
}

// firstChangedLine walks the patch's chunks and returns the 1-based line
// number on the new side where the first Add chunk begins. Returns 0 when
// the commit added the file as a whole (no patch context), when either blob
// side exceeds maxDiffBlobSize, or when the patch cannot be computed —
// callers treat 0 as "unknown".
func firstChangedLine(change *object.Change, from, to *object.File) int {
	if to != nil && to.Size > maxDiffBlobSize {
		return 0
	}
	if from != nil && from.Size > maxDiffBlobSize {
		return 0
	}
	patch, err := change.Patch()
	if err != nil || patch == nil {
		return 0
	}
	for _, fp := range patch.FilePatches() {
		if fp.IsBinary() {
			continue
		}
		newLine := 1
		for _, ch := range fp.Chunks() {
			lines := countLines(ch.Content())
			switch ch.Type() {
			case diff.Add:
				return newLine
			case diff.Equal:
				newLine += lines
			case diff.Delete:
				// no new-side advance
			}
		}
	}
	return 0
}

// addedHunks extracts every added hunk from a modification's diff, each
// bordered by up to diffContextLines lines of unchanged context, and returns
// them concatenated as the chunk's scan content. This replaces full-blob
// emission for modifications (#264): full-history previously emitted the
// entire new file on every commit that touched it, so a large,
// frequently-edited file was rescanned end to end on every touching commit.
// Only the actually-added material, plus enough context for regexes that
// span lines, is scanned now.
//
// ok=false means the diff was not computed (see maxDiffBlobSize) or the
// change added no lines (pure deletion or a no-content-change rename/mode
// change) — callers must skip the change, not fall back to full-file
// content, or the problem this function exists to fix comes right back.
func addedHunks(change *object.Change, from, to *object.File) ([]byte, bool) {
	if to != nil && to.Size > maxDiffBlobSize {
		return nil, false
	}
	if from != nil && from.Size > maxDiffBlobSize {
		return nil, false
	}
	patch, err := change.Patch()
	if err != nil || patch == nil {
		return nil, false
	}

	var out bytes.Buffer
	wrote := false
	for _, fp := range patch.FilePatches() {
		if fp.IsBinary() {
			continue
		}
		chunks := fp.Chunks()
		for i, c := range chunks {
			if c.Type() != diff.Add {
				continue
			}
			if out.Len() > 0 && out.Bytes()[out.Len()-1] != '\n' {
				out.WriteByte('\n')
			}
			out.WriteString(trailingContext(chunks, i, diffContextLines))
			out.WriteString(c.Content())
			out.WriteString(leadingContext(chunks, i, diffContextLines))
			wrote = true
		}
	}
	if !wrote {
		return nil, false
	}
	return out.Bytes(), true
}

// trailingContext returns up to n lines of context immediately preceding the
// Add chunk at index addIdx, skipping over any intervening Delete chunk
// (old-side-only text, not present in either the before or after common
// context) to reach the nearest Equal chunk. Stops with no context if that
// search hits the start of the file or another Add without finding one.
func trailingContext(chunks []diff.Chunk, addIdx, n int) string {
	for j := addIdx - 1; j >= 0; j-- {
		switch chunks[j].Type() {
		case diff.Equal:
			return lastNLines(chunks[j].Content(), n)
		case diff.Delete:
			continue
		default:
			return ""
		}
	}
	return ""
}

// leadingContext is trailingContext's mirror: up to n lines of context
// immediately following the Add chunk at index addIdx.
func leadingContext(chunks []diff.Chunk, addIdx, n int) string {
	for j := addIdx + 1; j < len(chunks); j++ {
		switch chunks[j].Type() {
		case diff.Equal:
			return firstNLines(chunks[j].Content(), n)
		case diff.Delete:
			continue
		default:
			return ""
		}
	}
	return ""
}

// lastNLines returns the trailing up-to-n lines of s, newline-terminated so
// it composes cleanly when a caller writes an Add chunk's content right
// after it.
func lastNLines(s string, n int) string {
	lines := splitLines(s)
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}

// firstNLines returns the leading up-to-n lines of s, newline-terminated.
func firstNLines(s string, n int) string {
	lines := splitLines(s)
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n") + "\n"
}

// splitLines splits diff chunk content into lines, dropping the trailing
// empty element strings.Split leaves behind when s ends in "\n" (every diff
// chunk boundary does except possibly the file's final line).
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			n++
		}
	}
	// A trailing line without newline still counts as a line on the new side.
	if s[len(s)-1] != '\n' {
		n++
	}
	return n
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(b[:n], 0x00) >= 0
}

var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)

// previousHeads returns every head hash recorded by the previous run — the
// union of the legacy single Head field and the multi-branch Heads slice —
// de-duplicated. Empty when there is no previous state (full scan).
func (s *Source) previousHeads() []plumbing.Hash {
	if !s.hasPreviousState || s.previousState == nil {
		return nil
	}
	seen := map[plumbing.Hash]struct{}{}
	var out []plumbing.Hash
	add := func(str string) {
		if str == "" {
			return
		}
		h := plumbing.NewHash(str)
		if h == plumbing.ZeroHash {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	add(s.previousState.Head)
	for _, h := range s.previousState.Heads {
		add(h)
	}
	return out
}

// newIncrementalState records the current head hash of every start ref so the
// next run can seed its stop-set. Head holds the first start (legacy single-
// branch readers stay compatible); Heads holds the full set.
func newIncrementalState(starts []plumbing.Hash) *incrementalState {
	st := &incrementalState{Version: 1}
	if len(starts) > 0 {
		st.Head = starts[0].String()
	}
	for _, h := range starts {
		st.Heads = append(st.Heads, h.String())
	}
	return st
}

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}
