// Package git walks local git history and emits changed blobs.
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
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const binarySniffLen = 512

const maxBlobSize int64 = 50 * 1024 * 1024 // 50 MiB

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
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int

	repoAbs  string
	branch   string
	maxDepth int
	since    time.Time
	include  []string
	exclude  []string

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int    `json:"version"`
	Head    string `json:"head"`
}

func (s *Source) Type() sources.SourceType { return sources.SourceGit }

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error {
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
	s.verify = verify
	s.concurrency = concurrency
	s.repoAbs = abs
	s.branch = cfg.Branch
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
	startHash, err := s.resolveStart(repo)
	if err != nil {
		return err
	}
	s.nextState = &incrementalState{Version: 1, Head: startHash.String()}

	stopHash, hasStop := s.previousHead()
	commits, err := s.collectCommits(repo, startHash, stopHash, hasStop)
	if err != nil {
		return err
	}

	for _, c := range commits {
		if err := ctx.Err(); err != nil {
			return err
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
	startHash, err := s.resolveStart(repo)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeHash(h, "git-v1")
	writeHash(h, s.repoAbs)
	writeHash(h, startHash.String())
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolveStart picks the commit hash to start the walk from.
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

// collectCommits returns commits in oldest-first order.
func (s *Source) collectCommits(repo *git.Repository, start, stop plumbing.Hash, hasStop bool) ([]*object.Commit, error) {
	iter, err := repo.Log(&git.LogOptions{From: start})
	if err != nil {
		return nil, fmt.Errorf("git: log: %w", err)
	}
	defer iter.Close()

	var commits []*object.Commit
	err = iter.ForEach(func(c *object.Commit) error {
		if hasStop && c.Hash == stop {
			return errStorerStop
		}
		if !s.since.IsZero() && c.Committer.When.Before(s.since) {
			return nil
		}
		commits = append(commits, c)
		if s.maxDepth > 0 && len(commits) >= s.maxDepth {
			return errStorerStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStorerStop) {
		return nil, fmt.Errorf("git: iterate commits: %w", err)
	}

	sort.SliceStable(commits, func(i, j int) bool {
		return commits[i].Committer.When.Before(commits[j].Committer.When)
	})
	return commits, nil
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
		_, to, err := change.Files()
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
		data, ok := readBlob(to)
		if !ok {
			continue
		}
		// Belt-and-suspenders: go-git's IsBinary uses sniff bytes, but a few
		// blob types (UTF-16 BOM-less) slip through. The NUL-byte test
		// matches what the filesystem source applies.
		if isBinary(data) {
			continue
		}

		line := firstChangedLine(change)
		chunk := &sources.Chunk{
			SourceID:   s.sourceID,
			SourceType: sources.SourceGit,
			SourceName: s.name,
			Data:       data,
			SourceMetadata: sources.Metadata{
				Git: &sources.GitMeta{
					Repository: s.repoAbs,
					Commit:     c.Hash.String(),
					File:       path,
					Line:       line,
					Email:      c.Committer.Email,
				},
			},
			Verify: s.verify,
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
// the commit added the file as a whole (no patch context) or when the patch
// cannot be computed — callers treat 0 as "unknown".
func firstChangedLine(change *object.Change) int {
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

// compile-time interface check
var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)

func (s *Source) previousHead() (plumbing.Hash, bool) {
	if !s.hasPreviousState || s.previousState == nil || s.previousState.Head == "" {
		return plumbing.ZeroHash, false
	}
	hash := plumbing.NewHash(s.previousState.Head)
	if hash == plumbing.ZeroHash {
		return plumbing.ZeroHash, false
	}
	return hash, true
}

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}
