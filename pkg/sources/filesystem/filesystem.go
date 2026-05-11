// Package filesystem is a Source that walks one or more paths and emits one
// Chunk per regular file. Symlinks are not followed; binary files and files
// larger than max_size_bytes are skipped. Permission errors during walk are
// silently skipped so a single unreadable directory does not abort the scan.
package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	"golang.org/x/sync/errgroup"
)

const defaultMaxSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB

// binarySniffLen is the prefix size used to classify a file as binary by
// presence of NUL bytes — matches what `file(1)` and git use.
const binarySniffLen = 512

func init() {
	sources.Register(sources.SourceFilesystem, func() sources.Source { return &Source{} })
}

// Config is the JSON shape passed to Init. Include / Exclude take
// `path/filepath.Match` glob syntax (no `**` recursion — directories
// pruned by walking the tree, not by globbing). Both lists are matched
// against the path RELATIVE to its config root, so `--exclude
// node_modules` does the right thing whether the user passes
// `./repo` or `/abs/path/repo`. Default-on excludes ship in
// commonExcludes (the .git, vendor, node_modules patterns every team
// turns off the same way) — set DisableDefaultExcludes to scan them.
type Config struct {
	Paths                  []string `json:"paths"`
	MaxSizeBytes           int64    `json:"max_size_bytes"`
	Include                []string `json:"include,omitempty"`
	Exclude                []string `json:"exclude,omitempty"`
	DisableDefaultExcludes bool     `json:"disable_default_excludes,omitempty"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config
	excludes    []string
}

// commonExcludes are skipped by default. Users can opt back in with
// DisableDefaultExcludes. Each entry matches a directory or file name
// (NOT a path) so a glob deep in the tree still applies.
//
// Two flavours live here side-by-side:
//   - directory basenames (.git, node_modules, vendor, …) — pruned via
//     fs.SkipDir before walking children, so they cost zero on cold paths.
//   - file basenames and globs (package-lock.json, *.min.js, *.map) —
//     these are dense streams of sha256/integrity hashes and minifier
//     output that sail past the generic high-entropy detector (entropy
//     ≥ 4.0) and were the dominant source of FP noise observed in real
//     scans. Excluded by default because nobody ships secrets in a
//     lockfile or a minified bundle; users who want them can opt back in
//     with DisableDefaultExcludes.
var commonExcludes = []string{
	// VCS / build / language sandboxes — directory basenames.
	".git",
	".hg",
	".svn",
	"node_modules",
	"vendor",
	"target",
	"dist",
	"build",
	"__pycache__",
	".venv",
	".tox",
	// Lockfiles. Hash-heavy, ship no real secrets, and dominate FPs.
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"Cargo.lock",
	"go.sum",
	"Pipfile.lock",
	"poetry.lock",
	"composer.lock",
	"Gemfile.lock",
	"mix.lock",
	"Podfile.lock",
	// Minified bundles and sourcemaps — entropy-dense by construction.
	// Globs are evaluated via filepath.Match against the basename in
	// excluded(); the same code path that already supports `*.env`.
	"*.min.js",
	"*.min.css",
	"*.map",
	"*.bundle.js",
}

func (s *Source) Type() sources.SourceType { return sources.SourceFilesystem }

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("filesystem: invalid config json: %w", err)
		}
	}
	if len(cfg.Paths) == 0 {
		return errors.New("filesystem: config.paths must contain at least one path")
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = defaultMaxSizeBytes
	}
	// Validate every root up front. A missing root is a user error and must
	// fail Init so the orchestrator does not silently scan nothing.
	for _, p := range cfg.Paths {
		if _, err := os.Lstat(p); err != nil {
			return fmt.Errorf("filesystem: path %q: %w", p, err)
		}
	}
	// Validate every glob pattern up front so a typo surfaces here
	// rather than mid-walk. filepath.Match returns ErrBadPattern for
	// unmatched brackets etc.; we treat that as a fatal config error.
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, ""); err != nil {
			return fmt.Errorf("filesystem: invalid glob %q: %w", p, err)
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
	s.cfg = cfg
	s.excludes = append([]string{}, cfg.Exclude...)
	if !cfg.DisableDefaultExcludes {
		s.excludes = append(s.excludes, commonExcludes...)
	}
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, s.concurrency)

	// Each root is walked sequentially; per-file reads are fanned out under
	// the semaphore so concurrency is bounded regardless of tree shape.
	for _, root := range s.cfg.Paths {
		root := root
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsPermission(walkErr) || errors.Is(walkErr, fs.ErrPermission) {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				// Missing files mid-walk are tolerated; only return on ctx errors.
				if errors.Is(walkErr, fs.ErrNotExist) {
					return nil
				}
				return walkErr
			}
			if err := gctx.Err(); err != nil {
				return err
			}
			// Directory pruning before per-entry checks: if a directory
			// matches any exclude, skip the whole subtree. This is the
			// payoff for default excludes — `node_modules` adds zero
			// walk cost when it's the first thing pruned.
			if d.IsDir() {
				if path != root && s.excluded(d.Name(), relPath(root, path)) {
					return fs.SkipDir
				}
				return nil
			}
			// Skip symlinks entirely — do not follow, do not emit. Lstat'd by WalkDir.
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel := relPath(root, path)
			if s.excluded(d.Name(), rel) {
				return nil
			}
			if !s.included(d.Name(), rel) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				if os.IsPermission(err) || errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if info.Size() > s.cfg.MaxSizeBytes {
				return nil
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				absPath = path
			}

			sem <- struct{}{}
			g.Go(func() error {
				defer func() { <-sem }()
				return s.emitFile(gctx, absPath, ch)
			})
			return nil
		}); err != nil {
			// Surface only ctx cancellation/walk-fatal; per-file errors are skipped above.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = g.Wait()
				return err
			}
			// Stop additional fanout but drain in-flight goroutines.
			_ = g.Wait()
			return err
		}
	}
	return g.Wait()
}

// emitFile reads path, classifies binary/text, and sends one Chunk. ctx is
// honoured both for cancellation during read and during channel send so a
// stalled consumer cannot pin the worker.
func (s *Source) emitFile(ctx context.Context, absPath string, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(absPath)
	if err != nil {
		// Permission / vanished files are skipped, not fatal.
		if os.IsPermission(err) || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return nil
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	if isBinary(data) {
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceFilesystem,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: absPath, Line: 1},
		},
		Verify: s.verify,
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// excluded returns true when name OR rel matches any exclude glob. We
// match against both the basename and the relative path so `vendor`
// (a basename) and `pkg/*/_generated/*` (a path glob) both work.
func (s *Source) excluded(name, rel string) bool {
	for _, g := range s.excludes {
		if matchGlob(g, name) || matchGlob(g, rel) {
			return true
		}
	}
	return false
}

// included returns true when no Include patterns are configured (the
// default — every file is included) or rel/name matches one. When
// Include is set, exclusion still wins: --exclude '*_test.go'
// --include 'pkg/**' won't include test files in pkg.
func (s *Source) included(name, rel string) bool {
	if len(s.cfg.Include) == 0 {
		return true
	}
	for _, g := range s.cfg.Include {
		if matchGlob(g, name) || matchGlob(g, rel) {
			return true
		}
	}
	return false
}

// matchGlob is filepath.Match with a tiny wrapper: a malformed pattern
// (already rejected at Init) must never panic mid-walk, so a runtime
// match error is treated as "no match" rather than fatal.
func matchGlob(pattern, name string) bool {
	ok, _ := filepath.Match(pattern, name)
	return ok
}

// relPath returns path relative to root using forward slashes so glob
// patterns are portable across OS. Returns the original path on error
// (rare — same volume guaranteed by the walk).
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// isBinary returns true if any of the first binarySniffLen bytes is NUL.
func isBinary(b []byte) bool {
	n := len(b)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(b[:n], 0x00) >= 0
}

// compile-time interface check
var _ sources.Source = (*Source)(nil)
