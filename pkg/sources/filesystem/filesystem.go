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

// Config is the JSON shape passed to Init.
type Config struct {
	Paths        []string `json:"paths"`
	MaxSizeBytes int64    `json:"max_size_bytes"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config
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
	if concurrency <= 0 {
		concurrency = 1
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.verify = verify
	s.concurrency = concurrency
	s.cfg = cfg
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
			// Skip symlinks entirely — do not follow, do not emit. Lstat'd by WalkDir.
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !d.Type().IsRegular() {
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
