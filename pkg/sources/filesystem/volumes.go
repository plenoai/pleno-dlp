package filesystem

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// volumeGroup is a resolved multi-volume archive: the sibling files that
// archive.JoinVolumes links into one logical stream, volume 1 first.
type volumeGroup struct {
	scheme  archive.VolumeScheme
	paths   []string
	members map[string]bool
}

// resolveVolumes groups the siblings of the volume-1 file first. It returns
// nil when fewer than two volumes link (a missing or unrelated second
// volume), in which case every file is scanned on its own and the archive
// walker reports the remaining split-volume gaps.
func (s *Source) resolveVolumes(root, first string, id archive.VolumeID) *volumeGroup {
	dir := filepath.Dir(first)
	paths := []string{first}
	var total int64
	for i := 1; i <= archive.MaxVolumes; i++ {
		path := first
		if i > 1 {
			path = filepath.Join(dir, id.Sibling(i))
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			break
		}
		if s.excluded(info.Name(), relPath(root, path)) || !s.included(info.Name(), relPath(root, path)) {
			break
		}
		total += info.Size()
		if total > s.cfg.MaxSizeBytes {
			return nil
		}
		if i > 1 {
			paths = append(paths, path)
		}
	}
	if term, ok := id.Terminal(); ok {
		path := filepath.Join(dir, term)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if fi, err := os.Lstat(first); err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		if s.excluded(info.Name(), relPath(root, path)) || !s.included(info.Name(), relPath(root, path)) {
			return nil
		}
		if total += info.Size(); total > s.cfg.MaxSizeBytes {
			return nil
		}
		paths = append(paths, path)
	}
	if len(paths) < 2 {
		return nil
	}
	_, closer, count, err := openVolumes(paths, id.Scheme, s.cfg.MaxSizeBytes)
	if err != nil {
		return nil
	}
	_ = closer.Close()
	if count < 2 {
		return nil
	}
	g := &volumeGroup{scheme: id.Scheme, members: map[string]bool{}}
	for _, p := range paths[:count] {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		g.paths = append(g.paths, p)
		g.members[p] = true
	}
	return g
}

// unchanged reports whether every volume matches the previous run's state.
func (s *Source) volumesUnchanged(g *volumeGroup) bool {
	for _, p := range g.paths {
		info, err := os.Stat(p)
		if err != nil || !s.fileUnchanged(p, stateForFile(info)) {
			return false
		}
	}
	return true
}

// openVolumes opens paths and joins them; count is how many linked.
func openVolumes(paths []string, scheme archive.VolumeScheme, maxTotal int64) (io.ReaderAt, io.Closer, int, error) {
	closers := make(multiCloser, 0, len(paths))
	vols := make([]archive.Volume, 0, len(paths))
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			_ = closers.Close()
			return nil, nil, 0, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			_ = closers.Close()
			return nil, nil, 0, errors.Join(err, archive.ErrVolumeChain)
		}
		closers = append(closers, &fileReaderAtCloser{file: f, size: info.Size(), modTime: info.ModTime()})
		vols = append(vols, archive.Volume{R: f, Size: info.Size()})
	}
	r, _, count, err := archive.JoinVolumes(scheme, vols, maxTotal)
	if err != nil {
		_ = closers.Close()
		return nil, nil, 0, err
	}
	return r, closers, count, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var errs []error
	for _, c := range m {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// emitVolumeGroup sends one chunk whose body is the joined volumes; its
// location is volume 1.
func (s *Source) emitVolumeGroup(ctx context.Context, g *volumeGroup, ch chan<- *sources.Chunk) error {
	maxSize := s.cfg.MaxSizeBytes
	first := g.paths[0]
	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceFilesystem,
		SourceName: s.name,
		Open: func(openCtx context.Context) (io.ReaderAt, io.Closer, int64, error) {
			if err := openCtx.Err(); err != nil {
				return nil, nil, 0, err
			}
			r, closer, count, err := openVolumes(g.paths, g.scheme, maxSize)
			if err != nil {
				return nil, nil, 0, err
			}
			if count != len(g.paths) {
				_ = closer.Close()
				return nil, nil, 0, errFileChangedDuringScan
			}
			return r, closer, r.(interface{ Size() int64 }).Size(), nil
		},
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: first, Line: 1},
		},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
