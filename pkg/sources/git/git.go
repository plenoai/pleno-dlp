// Package git walks local git history and emits added content per commit.
package git

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitfilesystem "github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/utils/merkletrie"
	"golang.org/x/sync/semaphore"

	archivepkg "github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const binarySniffLen = 512

const maxBlobSize int64 = 50 * 1024 * 1024 // 50 MiB

// Git artifact defaults remain conservative; callers may opt into larger
// work ceilings up to the TruffleHog-compatible 2 GiB values. Large artifact
// values are disk-spooled; see ADR 0004.
const (
	DefaultGitArtifactMaxBytes     int64 = 10 << 20
	DefaultArchiveMaxExpandedBytes int64 = 50 << 20
	MaxGitArtifactBytes            int64 = 2 << 30
	MaxArchiveExpandedBytes        int64 = 2 << 30
)

// ErrNoBranchHeads identifies repositories with no safe commit-bearing
// history refs. The name is retained for compatibility with existing callers.
var ErrNoBranchHeads = errors.New("git: no history refs to walk")

// maxDiffBlobSize bounds the blob size (either side) that firstChangedLine
// and addedHunks will run a diff over. change.Patch() reads both blob sides
// fully into strings with no cap of its own — maxBlobSize above does not
// protect this path — and then hands them to a Myers diff that expands them
// roughly 4x further as []rune. A single large text blob (SQL dump,
// lockfile, generated code) can therefore spike memory by multiple GiB.
// Above this bound emitCommit uses native git's streaming diff output and
// splits added content into maxDiffChunkSize pieces. firstChangedLine and
// addedHunks themselves still decline oversized blobs; callers must use the
// native fallback rather than full-blob emission, which would reintroduce
// the #264 memory/scan-bytes blowup.
const maxDiffBlobSize int64 = 1 << 20 // 1 MiB

// maxDiffChunkSize bounds chunks produced by native diff parsing. The fast
// history path rolls this window across arbitrarily large text hunks; the
// go-git fallback still caps total added/context content at maxBlobSize.
const maxDiffChunkSize = 1 << 20 // 1 MiB

const diffChunkOverlap = 512

const (
	artifactBudgetUnit     int64 = 1 << 20
	artifactBudgetCapacity int64 = 200 << 20
)

var aggregateArtifactBudget = semaphore.NewWeighted(artifactBudgetCapacity / artifactBudgetUnit)

func acquireArtifactBudget(ctx context.Context, bytes int64) (func(), time.Duration, error) {
	units := (bytes + artifactBudgetUnit - 1) / artifactBudgetUnit
	if units < 1 {
		units = 1
	}
	capacity := artifactBudgetCapacity / artifactBudgetUnit
	if units > capacity {
		units = capacity
	}
	start := time.Now()
	if err := aggregateArtifactBudget.Acquire(ctx, units); err != nil {
		return nil, time.Since(start), err
	}
	return func() { aggregateArtifactBudget.Release(units) }, time.Since(start), nil
}

func artifactBudgetWeight(includeArchives bool, blobBytes int64) int64 {
	if includeArchives {
		// Keep archive expansion serialized process-wide. Spooling bounds heap,
		// while serialization also bounds adversarial decompression CPU and disk
		// pressure across repository workers.
		return artifactBudgetCapacity
	}
	// Binary reads stream after go-git's large-object threshold. Retain the
	// conservative reservation to bound aggregate scan and spool pressure.
	if blobBytes >= artifactBudgetCapacity/2 {
		return artifactBudgetCapacity
	}
	return 2 * blobBytes
}

func withArtifactBudget(ctx context.Context, archive bool, blobBytes int64, fn func() error) error {
	weight := artifactBudgetWeight(archive, blobBytes)
	release, waited, err := acquireArtifactBudget(ctx, weight)
	if err != nil {
		return fmt.Errorf("git: artifact budget wait: %w", err)
	}
	defer release()
	if waited > 10*time.Millisecond {
		fmt.Fprintf(os.Stderr, "git: artifact budget waited %s for %d bytes\n", waited.Round(time.Millisecond), weight)
	}
	return fn()
}

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
	// AllBranches walks every reachable commit on safe advertised history
	// refs (HEAD, branches, remotes, tags, and GitHub pull-request refs), not
	// just the single resolved start. Pseudo refs such as replace/notes/stash
	// are excluded. Off by default so the existing single-branch contract is
	// byte-identical.
	AllBranches bool `json:"all_branches,omitempty"`
	// IncludeCommitMetadata emits one synthetic commit:metadata chunk per
	// commit containing the message, identities, and default git notes.
	// It is opt-in because author/committer emails are expected PII.
	IncludeCommitMetadata bool `json:"include_commit_metadata,omitempty"`
	// SkipMergeCommits omits merge-commit diffs while retaining every
	// non-merge commit. It is opt-in because merge-conflict resolutions can
	// introduce unique content.
	SkipMergeCommits bool `json:"skip_merge_commits,omitempty"`
	// TrufflehogCompatible matches trufflehog's Git diff surface: merge and
	// rename diffs are omitted and unchanged context keeps only newlines.
	TrufflehogCompatible    bool          `json:"trufflehog_compatible,omitempty"`
	IncludeGitArchives      bool          `json:"include_git_archives,omitempty"`
	IncludeGitBinaries      bool          `json:"include_git_binaries,omitempty"`
	GitArtifactMaxBytes     int64         `json:"git_artifact_max_bytes,omitempty"`
	ArchiveMaxExpandedBytes int64         `json:"archive_max_expanded_bytes,omitempty"`
	ArchiveMaxFiles         int           `json:"archive_max_files,omitempty"`
	ArchiveMaxDepth         int           `json:"archive_max_depth,omitempty"`
	ArchiveTimeout          time.Duration `json:"archive_timeout,omitempty"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	concurrency int

	repoAbs               string
	branch                string
	allBranches           bool
	maxDepth              int
	since                 time.Time
	include               []string
	exclude               []string
	includeCommitMetadata bool
	skipMergeCommits      bool
	trufflehogCompatible  bool
	includeGitArchives    bool
	includeGitBinaries    bool
	gitArtifactMaxBytes   int64
	archiveLimits         archivepkg.Limits
	archiveTimeout        time.Duration

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

func (s *Source) omitMergeDiffs() bool {
	return s.skipMergeCommits || s.trufflehogCompatible
}

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
	s.includeCommitMetadata = cfg.IncludeCommitMetadata
	s.skipMergeCommits = cfg.SkipMergeCommits
	s.trufflehogCompatible = cfg.TrufflehogCompatible
	s.includeGitArchives = cfg.IncludeGitArchives
	s.includeGitBinaries = cfg.IncludeGitBinaries
	s.gitArtifactMaxBytes = cfg.GitArtifactMaxBytes
	if s.gitArtifactMaxBytes <= 0 {
		s.gitArtifactMaxBytes = DefaultGitArtifactMaxBytes
	}
	s.archiveLimits = archivepkg.Limits{MaxDepth: cfg.ArchiveMaxDepth, MaxInputBytes: s.gitArtifactMaxBytes, MaxEntryBytes: s.gitArtifactMaxBytes, MaxExpandedBytes: cfg.ArchiveMaxExpandedBytes, MaxFiles: cfg.ArchiveMaxFiles}
	if s.archiveLimits.MaxDepth <= 0 {
		s.archiveLimits.MaxDepth = 3
	}
	if s.archiveLimits.MaxExpandedBytes <= 0 {
		s.archiveLimits.MaxExpandedBytes = DefaultArchiveMaxExpandedBytes
	}
	if s.archiveLimits.MaxFiles <= 0 {
		s.archiveLimits.MaxFiles = 1000
	}
	s.archiveTimeout = cfg.ArchiveTimeout
	if s.archiveTimeout <= 0 {
		s.archiveTimeout = 5 * time.Second
	}
	if s.gitArtifactMaxBytes > MaxGitArtifactBytes || s.archiveLimits.MaxExpandedBytes > MaxArchiveExpandedBytes || s.archiveLimits.MaxFiles > 10000 || s.archiveLimits.MaxDepth > 8 || s.archiveTimeout > time.Minute {
		return errors.New("git: artifact limits exceed hard caps (blob 2GiB, expanded 2GiB, files 10000, depth 8, timeout 1m)")
	}
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if s.trufflehogCompatible {
		fmt.Fprintln(os.Stderr, "git: diff surface: trufflehog-compatible")
	}
	repo, err := openBoundedRepository(s.repoAbs, archivepkg.SpillThreshold)
	if err != nil {
		return fmt.Errorf("git: reopen repo: %w", err)
	}
	starts, err := s.resolveStarts(repo)
	if err != nil {
		return err
	}
	// Publish the new heads only after every collected commit was covered.
	// Advancing a checkpoint after a missing tree/object would make the retry
	// stop at the very commit whose content was skipped.
	candidateState := newIncrementalState(starts)
	s.nextState = nil

	stops := s.previousHeads()
	if s.nativeFastPathEligible(len(starts)) {
		if gitBin, lookupErr := exec.LookPath("git"); lookupErr == nil {
			supported, probeErr := s.nativeFastPathSupported(ctx, gitBin, starts[0])
			if probeErr != nil {
				if errors.Is(probeErr, context.Canceled) || errors.Is(probeErr, context.DeadlineExceeded) {
					return probeErr
				}
				s.retainPreviousState()
				return s.nativeDegradedError(probeErr)
			}
			if supported {
				nativeStops, stopErr := nativeExistingStops(ctx, repo, stops)
				if stopErr != nil {
					s.retainPreviousState()
					return s.nativeDegradedError(stopErr)
				}
				if err := s.chunksNative(ctx, repo, gitBin, starts, nativeStops, ch); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					s.retainPreviousState()
					return s.nativeDegradedError(err)
				}
				s.nextState = candidateState
				return nil
			}
		}
	}

	refs, err := s.collectCommits(ctx, repo, starts, stops)
	if err != nil {
		return err
	}

	// refs holds only hash+timestamp (see collectCommits); re-fetch each
	// *object.Commit here rather than holding the whole history's commit
	// objects live at once. go-git's object storer caches recently decoded
	// objects, so this re-fetch is cheap for commits we just walked.
	var coverage []engine.ScanFailure
	coverageTotal := 0
	recordCoverage := func(commit plumbing.Hash, stage string, err error) {
		coverageTotal++
		if len(coverage) < 32 {
			coverage = append(coverage, engine.ScanFailure{
				Kind:   engine.FailureSource,
				Source: fmt.Sprintf("%s@%s:%s", s.repoAbs, commit, stage),
				Err:    err,
			})
		}
	}
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, err := repo.CommitObject(r.hash)
		if err != nil {
			recordCoverage(r.hash, "commit", fmt.Errorf("git: load commit %s: %w", r.hash, err))
			continue
		}
		if err := s.emitCommit(ctx, c, ch); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recordCoverage(c.Hash, "tree-diff", err)
		}
	}
	if coverageTotal > 0 {
		if s.previousState != nil {
			previous := *s.previousState
			previous.Heads = append([]string(nil), s.previousState.Heads...)
			s.nextState = &previous
		}
		return &engine.DegradedError{Total: coverageTotal, Counts: map[engine.FailureKind]int{engine.FailureSource: coverageTotal}, Failures: coverage}
	}
	s.nextState = candidateState
	return nil
}

// openBoundedRepository replaces PlainOpen's unlimited filesystem object
// hydration with go-git's lazy large-object reader. This applies to loose and
// packed (including delta-compressed) objects before any Blob.Reader call.
func openBoundedRepository(path string, threshold int64) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}
	storage, ok := repo.Storer.(*gitfilesystem.Storage)
	if !ok {
		return nil, fmt.Errorf("git: unsupported repository storage %T", repo.Storer)
	}
	repo.Storer = gitfilesystem.NewStorageWithOptions(storage.Filesystem(), cache.NewObjectLRUDefault(), gitfilesystem.Options{
		LargeObjectThreshold: threshold,
	})
	return repo, nil
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
// AllBranches=true it is HEAD plus every safe advertised history ref, with
// annotated tags peeled to commits and identical commit hashes collapsed. A
// branch override always pins to that one branch regardless of AllBranches.
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
		hash, include, err := AdvertisedHistoryRefCommit(repo, ref)
		if err != nil {
			return err
		}
		if !include {
			return nil
		}
		add(hash)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("git: iterate references: %w", err)
	}
	if len(starts) == 0 {
		return nil, ErrNoBranchHeads
	}
	return starts, nil
}

// AdvertisedHistoryRefCommit returns the commit selected by a ref that is
// safe to use as a full-history root. The allowlist deliberately excludes
// pseudo refs such as refs/replace, refs/notes, refs/stash, and bisect refs.
// Tags are peeled so annotated-tag object IDs never enter commit walks or
// incremental stop sets; tags whose final target is not a commit are skipped.
func AdvertisedHistoryRefCommit(repo *git.Repository, ref *plumbing.Reference) (plumbing.Hash, bool, error) {
	if ref == nil || ref.Type() != plumbing.HashReference {
		return plumbing.ZeroHash, false, nil
	}
	name := ref.Name().String()
	allowed := strings.HasPrefix(name, "refs/heads/") ||
		strings.HasPrefix(name, "refs/remotes/") ||
		strings.HasPrefix(name, "refs/tags/") ||
		IsGitHubPullRequestRef(ref.Name())
	if !allowed {
		return plumbing.ZeroHash, false, nil
	}
	if strings.HasPrefix(name, "refs/tags/") {
		hash := ref.Hash()
		seen := make(map[plumbing.Hash]struct{})
		for depth := 0; depth < 64; depth++ {
			if _, duplicate := seen[hash]; duplicate {
				return plumbing.ZeroHash, false, fmt.Errorf("git: cyclic tag history ref %q", name)
			}
			seen[hash] = struct{}{}
			peeled, err := repo.Storer.EncodedObject(plumbing.AnyObject, hash)
			if err != nil {
				return plumbing.ZeroHash, false, fmt.Errorf("git: load history ref %q: %w", name, err)
			}
			switch peeled.Type() {
			case plumbing.CommitObject:
				return hash, true, nil
			case plumbing.TagObject:
				tag, err := repo.TagObject(hash)
				if err != nil {
					return plumbing.ZeroHash, false, fmt.Errorf("git: peel history ref %q: %w", name, err)
				}
				hash = tag.Target
			default:
				return plumbing.ZeroHash, false, nil
			}
		}
		return plumbing.ZeroHash, false, fmt.Errorf("git: tag history ref %q exceeds peel depth 64", name)
	}
	if _, err := repo.CommitObject(ref.Hash()); err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("git: resolve history ref %q: %w", name, err)
	}
	return ref.Hash(), true, nil
}

// IsGitHubPullRequestRef reports whether name is an exact GitHub-advertised
// pull-request head or merge ref. It intentionally rejects adjacent pseudo
// refs so callers can safely filter an untrusted remote advertisement.
func IsGitHubPullRequestRef(name plumbing.ReferenceName) bool {
	rest, ok := strings.CutPrefix(name.String(), "refs/pull/")
	if !ok {
		return false
	}
	number, kind, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(kind, "/") || (kind != "head" && kind != "merge") {
		return false
	}
	id, err := strconv.ParseUint(number, 10, 64)
	return err == nil && id > 0
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
func (s *Source) collectCommits(ctx context.Context, repo *git.Repository, starts []plumbing.Hash, stops []plumbing.Hash) ([]commitRef, error) {
	seen := boundarySet(stops)

	var refs []commitRef

	for _, start := range starts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[start] {
			continue
		}
		startCommit, err := repo.CommitObject(start)
		if err != nil {
			return nil, fmt.Errorf("git: resolve start %s: %w", start, err)
		}
		iter := object.NewCommitPreorderIter(startCommit, seen, nil)
		err = iter.ForEach(func(c *object.Commit) error {
			if err := ctx.Err(); err != nil {
				return err
			}
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
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
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
	if s.omitMergeDiffs() && c.NumParents() > 1 {
		if s.includeCommitMetadata {
			return s.emitCommitMetadata(ctx, c, ch)
		}
		return nil
	}
	var partialErrs []error
	newTree, err := c.Tree()
	if err != nil {
		return fmt.Errorf("git: load tree for commit %s: %w", c.Hash, err)
	}

	var oldTree *object.Tree
	if c.NumParents() > 0 {
		parent, err := c.Parent(0)
		if err != nil {
			return fmt.Errorf("git: load parent for commit %s: %w", c.Hash, err)
		}
		oldTree, err = parent.Tree()
		if err != nil {
			return fmt.Errorf("git: load parent tree for commit %s parent %s: %w", c.Hash, parent.Hash, err)
		}
	}

	changes, err := object.DiffTreeWithOptions(ctx, oldTree, newTree, &object.DiffTreeOptions{})
	if err == nil && s.trufflehogCompatible {
		changes, err = detectTrufflehogRenames(changes)
	}
	if err != nil {
		return fmt.Errorf("git: diff tree for commit %s: %w", c.Hash, normalizeGitTreeDiffError(err))
	}

	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		from, to, err := change.Files()
		if err != nil {
			changePath := change.To.Name
			if changePath == "" {
				changePath = change.From.Name
			}
			partialErrs = append(partialErrs, fmt.Errorf("git: resolve changed file %q at %s: %w", changePath, c.Hash, err))
			continue
		}
		if to == nil {
			// Pure deletions have no `to` file — there is nothing to scan.
			continue
		}
		if s.trufflehogCompatible && from != nil && change.From.Name != change.To.Name {
			// Trufflehog's full-history command uses --diff-filter=AM, which
			// excludes paths classified as renames.
			continue
		}
		if s.trufflehogCompatible && from != nil && !sameGitDiffType(change.From.TreeEntry.Mode, change.To.TreeEntry.Mode) {
			// --diff-filter=AM also excludes type changes such as a regular
			// file becoming a symlink. Executable-bit changes remain M.
			continue
		}
		path := change.To.Name
		if !s.pathAllowed(path) {
			continue
		}

		bin, err := to.IsBinary()
		if err != nil {
			partialErrs = append(partialErrs, fmt.Errorf("git: classify %s at %s: %w", path, c.Hash, err))
			continue
		}
		if bin && !s.includeGitArchives && !s.includeGitBinaries {
			continue
		}
		commitMsg := c.Message
		if nl := strings.IndexByte(commitMsg, '\n'); nl >= 0 {
			commitMsg = commitMsg[:nl]
		}
		emitSegment := func(sendCtx context.Context, segment diffSegment) error {
			// Belt-and-suspenders: go-git's IsBinary uses sniff bytes, but a few
			// blob types (UTF-16 BOM-less) slip through. The NUL-byte test
			// matches what the filesystem source applies.
			if !bin && isBinary(segment.data) {
				return nil
			}
			segmentPath := path
			if segment.path != "" {
				segmentPath = segment.path
			}
			chunk := &sources.Chunk{
				SourceID:   s.sourceID,
				SourceType: sources.SourceGit,
				SourceName: s.name,
				Data:       segment.data,
				SourceMetadata: sources.Metadata{
					Git: &sources.GitMeta{
						Repository:   s.repoAbs,
						Commit:       c.Hash.String(),
						File:         segmentPath,
						Line:         segment.line,
						Email:        c.Author.Email,
						Author:       c.Author.Name,
						AuthoredDate: c.Author.When.UTC().Format(time.RFC3339),
						Message:      commitMsg,
					},
				},
			}
			select {
			case ch <- chunk:
				return nil
			case <-sendCtx.Done():
				return sendCtx.Err()
			}
		}
		// A from==nil change (file added, or the insert half of a rename
		// under DetectRenames:false above) has no prior version to diff
		// against — the whole file IS the new content, so full-blob
		// emission here is a one-time cost, not the repeated-rescan
		// blowup #264 targets. A genuine modification instead emits only
		// the added hunks (+ context): the full new blob would otherwise
		// be re-emitted on every commit that touches the file.
		var segments []diffSegment
		if bin {
			if to.Size < 0 || to.Size > s.gitArtifactMaxBytes {
				return fmt.Errorf("git: artifact %s at %s: %w", path, c.Hash, &archivepkg.PartialError{Kind: "max-blob-bytes", Entry: path, Err: fmt.Errorf("exceeds %d-byte limit", s.gitArtifactMaxBytes)})
			}
			isArchive := false
			if s.includeGitArchives {
				isArchive, err = blobLooksLikeArchive(ctx, to)
				if err != nil {
					return fmt.Errorf("git: inspect artifact %s at %s: %w", path, c.Hash, &archivepkg.PartialError{Kind: "corrupt-blob", Entry: path, Err: err})
				}
			}
			if !isArchive && !s.includeGitBinaries {
				continue
			}
			artifactErr := withArtifactBudget(ctx, isArchive, to.Size, func() error {
				if isArchive {
					reader, err := to.Reader()
					if err != nil {
						return fmt.Errorf("git: open archive %s at %s: %w", path, c.Hash, err)
					}
					archiveCtx, cancel := context.WithTimeout(ctx, s.archiveTimeout)
					walkErr := archivepkg.WalkStreamContext(archiveCtx, path, reader, to.Size, s.archiveLimits, func(entry archivepkg.StreamEntry) error {
						return streamBlob(archiveCtx, entry.Reader, entry.Size, func(segment diffSegment) error {
							segment.path = entry.Path
							return emitSegment(archiveCtx, segment)
						})
					})
					closeErr := reader.Close()
					cancel()
					if err := ctx.Err(); err != nil {
						return err
					}
					if walkErr != nil {
						partialErrs = append(partialErrs, fmt.Errorf("git: expand archive %s at %s: %w", path, c.Hash, walkErr))
					}
					if closeErr != nil {
						partialErrs = append(partialErrs, fmt.Errorf("git: close archive %s at %s: %w", path, c.Hash, closeErr))
					}
					return nil
				}
				reader, err := to.Reader()
				if err != nil {
					return fmt.Errorf("git: open binary %s at %s: %w", path, c.Hash, err)
				}
				spoolErr := archivepkg.WithSpoolContext(ctx, reader, to.Size, s.gitArtifactMaxBytes, func(validated io.Reader) error {
					return streamBlob(ctx, validated, to.Size, func(segment diffSegment) error {
						return emitSegment(ctx, segment)
					})
				})
				closeErr := reader.Close()
				if err := ctx.Err(); err != nil {
					return err
				}
				if spoolErr != nil || closeErr != nil {
					return fmt.Errorf("git: stream binary %s at %s: %w", path, c.Hash, &archivepkg.PartialError{Kind: "corrupt-blob", Entry: path, Err: errors.Join(spoolErr, closeErr)})
				}
				return nil
			})
			if artifactErr != nil {
				return artifactErr
			}
			continue
		} else if from == nil {
			data, ok := readBlob(to)
			if ok {
				segments = splitBlob(data)
			}
		} else if from.Size <= maxDiffBlobSize && to.Size <= maxDiffBlobSize {
			data, ok := addedHunks(change, from, to, s.trufflehogCompatible)
			if ok {
				segments = []diffSegment{{data: data, line: firstChangedLine(change, from, to)}}
			}
		} else {
			segments, err = s.nativeAddedHunks(ctx, c, path)
			if err != nil {
				return fmt.Errorf("git: stream large diff for %s at %s: %w", path, c.Hash, err)
			}
		}
		if len(segments) == 0 {
			continue
		}
		for _, segment := range segments {
			if err := emitSegment(ctx, segment); err != nil {
				return err
			}
		}
	}
	if s.includeCommitMetadata {
		if err := s.emitCommitMetadata(ctx, c, ch); err != nil {
			return err
		}
	}
	return errors.Join(partialErrs...)
}

func normalizeGitTreeDiffError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.HasSuffix(message, `": contains control character`) &&
		(strings.HasPrefix(message, `from: invalid path "`) || strings.HasPrefix(message, `to: invalid path "`)) {
		// The path is attacker-controlled repository data. Keep it out of logs
		// while preserving a typed, immutable coverage gap for explicit policy.
		return &archivepkg.PartialError{
			Kind:  "invalid-tree-path",
			Entry: "redacted",
			Err:   errors.New("git tree path contains a control character"),
		}
	}
	return err
}

// CorruptArchiveGapOnly reports whether every failed coverage leaf is an
// explicitly classifiable corrupt archive or archive symlink policy skip.
// Budget, depth, invalid-path, timeout, cleanup, and detector errors remain
// fail-closed and must not advance repository checkpoints.
func CorruptArchiveGapOnly(err error) bool {
	if err == nil {
		return false
	}
	if partial, ok := err.(*archivepkg.PartialError); ok {
		switch partial.Kind {
		case "corrupt-archive", "corrupt-entry", "symlink":
			return true
		default:
			return false
		}
	}
	if degraded, ok := err.(*engine.DegradedError); ok {
		if degraded.Total == 0 || degraded.Total != len(degraded.Failures) {
			return false
		}
		for _, failure := range degraded.Failures {
			if failure.Kind == engine.FailureDetector || !CorruptArchiveGapOnly(failure.Err) {
				return false
			}
		}
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !CorruptArchiveGapOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return CorruptArchiveGapOnly(wrapped.Unwrap())
	}
	return false
}

type diffSegment struct {
	data []byte
	line int
	path string
}

func blobLooksLikeArchive(ctx context.Context, file *object.File) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	reader, err := file.Reader()
	if err != nil {
		return false, err
	}
	prefix := make([]byte, 512)
	n, readErr := io.ReadFull(reader, prefix)
	closeErr := reader.Close()
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return false, errors.Join(readErr, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	return archivepkg.LooksLikeArchive(prefix[:n]), nil
}

// streamBlob emits one owned chunk at a time with the same 1 MiB windows and
// 512-byte overlap as splitBlob. Callers validate and spool the complete input
// before invoking this helper, so no corrupt partial value is emitted.
func streamBlob(ctx context.Context, reader io.Reader, expected int64, emit func(diffSegment) error) error {
	if reader == nil || emit == nil || expected < 0 {
		return errors.New("git: invalid blob stream")
	}
	windowCapacity := int64(maxDiffChunkSize + 1)
	if expected < int64(maxDiffChunkSize) {
		windowCapacity = expected + 1
	}
	window := make([]byte, 0, int(windowCapacity))
	var readBytes int64
	line := 1
	eof := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !eof {
			oldLen := len(window)
			window = window[:cap(window)]
			n, err := io.ReadFull(reader, window[oldLen:])
			window = window[:oldLen+n]
			readBytes += int64(n)
			switch err {
			case nil:
			case io.EOF, io.ErrUnexpectedEOF:
				eof = true
			default:
				return err
			}
		}
		if eof && readBytes != expected {
			return fmt.Errorf("git: blob stream size %d, want %d", readBytes, expected)
		}
		if len(window) == 0 {
			return nil
		}
		if eof && len(window) <= maxDiffChunkSize {
			return emit(diffSegment{data: append([]byte(nil), window...), line: line})
		}

		chunk := append([]byte(nil), window[:maxDiffChunkSize]...)
		if err := emit(diffSegment{data: chunk, line: line}); err != nil {
			return err
		}
		next := maxDiffChunkSize - diffChunkOverlap
		line += bytes.Count(window[:next], []byte{'\n'})
		carry := make([]byte, len(window)-next, maxDiffChunkSize+1)
		copy(carry, window[next:])
		window = carry
	}
}

// splitBlob bounds newly-added text files just like streamed modification
// diffs. Adjacent chunks overlap so detector tokens crossing a byte boundary
// are still visible in at least one chunk.
func splitBlob(data []byte) []diffSegment {
	if len(data) <= maxDiffChunkSize {
		return []diffSegment{{data: data, line: 1}}
	}
	var out []diffSegment
	start, line := 0, 1
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

func (s *Source) emitCommitMetadata(ctx context.Context, c *object.Commit, ch chan<- *sources.Chunk) error {
	var data strings.Builder
	fmt.Fprintf(&data, "message: %s\nauthor: %s <%s>\ncommitter: %s <%s>\n",
		c.Message, c.Author.Name, c.Author.Email, c.Committer.Name, c.Committer.Email)
	notes, err := s.commitNotes(ctx, c.Hash)
	if err != nil {
		return fmt.Errorf("git: read notes for %s: %w", c.Hash, err)
	}
	if notes != "" {
		fmt.Fprintf(&data, "notes: %s\n", notes)
	}
	chunk := &sources.Chunk{
		SourceID: s.sourceID, SourceType: sources.SourceGit, SourceName: s.name,
		Data: []byte(data.String()),
		SourceMetadata: sources.Metadata{Git: &sources.GitMeta{
			Repository: s.repoAbs, Commit: c.Hash.String(), File: "commit:metadata/" + c.Hash.String(), Line: 1,
			Email: c.Author.Email, Author: c.Author.Name,
			AuthoredDate: c.Author.When.UTC().Format(time.RFC3339), Message: strings.SplitN(c.Message, "\n", 2)[0],
		}},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Source) commitNotes(ctx context.Context, hash plumbing.Hash) (string, error) {
	refsCmd := exec.CommandContext(ctx, "git", "-C", s.repoAbs, "for-each-ref", "--format=%(refname)", "refs/notes")
	refsOut, err := refsCmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", nil // messages still scan on git-less hosts; notes are unavailable
		}
		return "", err
	}
	refs := strings.Fields(string(refsOut))
	sort.Strings(refs)
	var notes strings.Builder
	for _, ref := range refs {
		cmd := exec.CommandContext(ctx, "git", "-C", s.repoAbs, "notes", "--ref="+ref, "show", hash.String())
		out, err := cmd.Output()
		if err == nil {
			fmt.Fprintf(&notes, "[%s] %s\n", ref, strings.TrimSpace(string(out)))
			continue
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			continue // this notes ref has no note for the commit
		}
		return "", err
	}
	return strings.TrimSpace(notes.String()), nil
}

// nativeAddedHunks streams a single large modification through native git.
// go-git's Patch materializes both blobs and the Myers matrix, so it remains
// reserved for small files. Native git produces a bounded stdout stream; this
// parser retains only added lines and three lines of diff context and splits
// output into maxDiffChunkSize pieces with a small detector-boundary overlap.
// In trufflehog-compatible mode unchanged context keeps only its newlines.
func (s *Source) nativeAddedHunks(ctx context.Context, c *object.Commit, path string) ([]diffSegment, error) {
	if c.NumParents() == 0 {
		return nil, nil
	}
	parent, err := c.Parent(0)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "git", "-C", s.repoAbs, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=3", parent.Hash.String(), c.Hash.String(), "--", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var segments []diffSegment
	var buf []byte
	totalBytes := int64(0)
	overLimit := false
	lineNo := 0
	segmentLine := 0
	inHunk := false
	flush := func(overlap bool) {
		if len(buf) == 0 {
			return
		}
		if segmentLine == 0 {
			segmentLine = lineNo
		}
		segments = append(segments, diffSegment{data: append([]byte(nil), buf...), line: segmentLine})
		if overlap && len(buf) > diffChunkOverlap {
			buf = append([]byte(nil), buf[len(buf)-diffChunkOverlap:]...)
		} else {
			buf = nil
		}
		segmentLine = lineNo
	}
	appendData := func(data []byte) {
		if overLimit {
			return
		}
		if totalBytes+int64(len(data)) > maxBlobSize {
			overLimit = true
			return
		}
		totalBytes += int64(len(data))
		for len(data) > 0 {
			room := maxDiffChunkSize - len(buf)
			if room == 0 {
				flush(true)
				room = maxDiffChunkSize - len(buf)
			}
			if room > len(data) {
				room = len(data)
			}
			buf = append(buf, data[:room]...)
			data = data[room:]
		}
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), int(maxBlobSize)+1)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "@@ ") {
			flush(false)
			newStart, ok := newHunkStart(line)
			if !ok {
				inHunk = false
				continue
			}
			lineNo, segmentLine, inHunk = newStart, 0, true
			continue
		}
		if !inHunk || len(line) == 0 {
			continue
		}
		switch line[0] {
		case '+':
			if segmentLine == 0 {
				segmentLine = lineNo
			}
			appendData(append([]byte(line[1:]), '\n'))
			lineNo++
		case ' ':
			if s.trufflehogCompatible {
				appendData([]byte{'\n'})
			} else {
				appendData(append([]byte(line[1:]), '\n'))
			}
			lineNo++
		case '-':
			// old-side only
		case '\\':
			// "No newline at end of file" marker
		default:
			inHunk = false
		}
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if scanErr != nil {
		return nil, scanErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	if overLimit {
		return nil, fmt.Errorf("added diff content exceeds %d-byte limit", maxBlobSize)
	}
	flush(false)
	return segments, nil
}

func newHunkStart(header string) (int, bool) {
	plus := strings.IndexByte(header, '+')
	if plus < 0 {
		return 0, false
	}
	start := plus + 1
	end := start
	for end < len(header) && header[end] >= '0' && header[end] <= '9' {
		end++
	}
	if end == start {
		return 0, false
	}
	n, err := strconv.Atoi(header[start:end])
	return n, err == nil
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
	return readBlobLimit(f, maxBlobSize)
}

func readBlobLimit(f *object.File, limit int64) ([]byte, bool) {
	if f == nil || f.Size > limit {
		return nil, false
	}
	rdr, err := f.Reader()
	if err != nil {
		return nil, false
	}
	defer rdr.Close()
	data, err := io.ReadAll(io.LimitReader(rdr, limit+1))
	if err != nil {
		return nil, false
	}
	if int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}

// firstChangedLine walks the patch's chunks and returns the 1-based line
// number on the new side where the first Add chunk begins. Returns 0 when
// the commit added the file as a whole (no patch context), when either blob
// side exceeds maxDiffBlobSize, or when the patch cannot be computed —
// callers treat 0 as "unknown".
func gitRenameOptions(trufflehogCompatible bool) *object.DiffTreeOptions {
	if !trufflehogCompatible {
		return &object.DiffTreeOptions{}
	}
	return &object.DiffTreeOptions{
		DetectRenames: true,
		RenameScore:   50,   // Git --find-renames default.
		RenameLimit:   1000, // Git diff.renameLimit default.
	}
}

func detectTrufflehogRenames(changes object.Changes) (object.Changes, error) {
	fromModes := make(map[string]filemode.FileMode, len(changes))
	toModes := make(map[string]filemode.FileMode, len(changes))
	normalized := make(object.Changes, 0, len(changes))
	contentRenameBounded := true
	for _, change := range changes {
		copy := *change
		if copy.From.Name != "" {
			fromModes[copy.From.Name] = copy.From.TreeEntry.Mode
			copy.From.TreeEntry.Mode = normalizeGitBlobMode(copy.From.TreeEntry.Mode)
		}
		if copy.To.Name != "" {
			toModes[copy.To.Name] = copy.To.TreeEntry.Mode
			copy.To.TreeEntry.Mode = normalizeGitBlobMode(copy.To.TreeEntry.Mode)
		}
		action, err := copy.Action()
		if err != nil {
			return nil, err
		}
		if action == merkletrie.Insert || action == merkletrie.Delete {
			from, to, err := copy.Files()
			if err != nil {
				return nil, err
			}
			candidate := to
			if candidate == nil {
				candidate = from
			}
			if candidate != nil && candidate.Size > maxDiffBlobSize {
				contentRenameBounded = false
			}
		}
		normalized = append(normalized, &copy)
	}
	options := gitRenameOptions(true)
	if !contentRenameBounded {
		// go-git's similarity index streams bytes but can grow with distinct
		// blocks. Exact-hash rename detection is metadata-only and still catches
		// ordinary moves; large modified moves remain additions (safe over-scan).
		options.OnlyExactRenames = true
	}
	detected, err := object.DetectRenames(normalized, options)
	if err != nil {
		return nil, err
	}
	for _, change := range detected {
		if mode, ok := fromModes[change.From.Name]; ok {
			change.From.TreeEntry.Mode = mode
		}
		if mode, ok := toModes[change.To.Name]; ok {
			change.To.TreeEntry.Mode = mode
		}
	}
	return detected, nil
}

func normalizeGitBlobMode(mode filemode.FileMode) filemode.FileMode {
	switch mode {
	case filemode.Regular, filemode.Deprecated, filemode.Executable:
		return filemode.Regular
	default:
		return mode
	}
}

func sameGitDiffType(from, to filemode.FileMode) bool {
	return normalizeGitBlobMode(from) == normalizeGitBlobMode(to)
}

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
func addedHunks(change *object.Change, from, to *object.File, blankContext bool) ([]byte, bool) {
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
			trailing := trailingContext(chunks, i, diffContextLines)
			leading := leadingContext(chunks, i, diffContextLines)
			if blankContext {
				trailing = blankDiffContext(trailing)
				leading = blankDiffContext(leading)
			}
			out.WriteString(trailing)
			out.WriteString(c.Content())
			out.WriteString(leading)
			wrote = true
		}
	}
	if !wrote {
		return nil, false
	}
	return out.Bytes(), true
}

func blankDiffContext(context string) string {
	lines := strings.Count(context, "\n")
	if context != "" && !strings.HasSuffix(context, "\n") {
		lines++
	}
	return strings.Repeat("\n", lines)
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
