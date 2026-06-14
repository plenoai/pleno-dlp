// Package filesystem walks local paths and emits one chunk per regular file.
package filesystem

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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"golang.org/x/sync/errgroup"
)

const defaultMaxSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB

const binarySniffLen = 512

func init() {
	sources.Register(sources.SourceFilesystem, func() sources.Source { return &Source{} })
}

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

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int                             `json:"version"`
	Files   map[string]fileIncrementalState `json:"files"`
}

type fileIncrementalState struct {
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModTime int64  `json:"mod_time"`
}

// commonExcludes are skipped unless DisableDefaultExcludes is set.
var commonExcludes = []string{
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
	for _, p := range cfg.Paths {
		if _, err := os.Lstat(p); err != nil {
			return fmt.Errorf("filesystem: path %q: %w", p, err)
		}
	}
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
	s.nextState = &incrementalState{Version: 1, Files: map[string]fileIncrementalState{}}

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
			if d.IsDir() {
				if path != root && s.excluded(d.Name(), relPath(root, path)) {
					return fs.SkipDir
				}
				return nil
			}
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
			fileState := stateForFile(info)
			s.nextState.Files[absPath] = fileState
			if s.fileUnchanged(absPath, fileState) {
				return nil
			}

			sem <- struct{}{}
			g.Go(func() error {
				defer func() { <-sem }()
				return s.emitFile(gctx, absPath, ch)
			})
			return nil
		}); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = g.Wait()
				return err
			}
			_ = g.Wait()
			return err
		}
	}
	return g.Wait()
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
	if state.Files == nil {
		state.Files = map[string]fileIncrementalState{}
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

func (s *Source) fileUnchanged(path string, current fileIncrementalState) bool {
	if !s.hasPreviousState || s.previousState == nil {
		return false
	}
	prev, ok := s.previousState.Files[path]
	return ok && prev == current
}

// ResourceFingerprint hashes the resource set without rereading file bytes.
func (s *Source) ResourceFingerprint(ctx context.Context) (string, error) {
	h := sha256.New()
	writeHash(h, "filesystem-v1")
	for _, root := range s.cfg.Paths {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			absRoot = root
		}
		writeHash(h, absRoot)
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsPermission(walkErr) || errors.Is(walkErr, fs.ErrPermission) {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if errors.Is(walkErr, fs.ErrNotExist) {
					return nil
				}
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && s.excluded(d.Name(), relPath(root, path)) {
					return fs.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			rel := relPath(root, path)
			if s.excluded(d.Name(), rel) || !s.included(d.Name(), rel) {
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
			writeHash(h, rel)
			writeHash(h, fmt.Sprintf("%d:%d:%d", info.Size(), info.Mode().Perm(), info.ModTime().UnixNano()))
			return nil
		}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	if isBinary(data) && !archive.LooksLikeArchive(data) {
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
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)

func stateForFile(info fs.FileInfo) fileIncrementalState {
	return fileIncrementalState{
		Size:    info.Size(),
		Mode:    uint32(info.Mode().Perm()),
		ModTime: info.ModTime().UnixNano(),
	}
}

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}
