// Package archive expands zip, tar, gzip, and bzip2 payloads into leaf entries.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Entry is one expanded file from inside an archive.
type Entry struct {
	Path string
	Data []byte
}

// PartialError identifies incomplete archive coverage while allowing callers
// to scan entries successfully extracted before or beside the failure.
type PartialError struct {
	Kind, Entry string
	Err         error
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("archive %s (%s): %v", e.Kind, e.Entry, e.Err)
}
func (e *PartialError) Unwrap() error { return e.Err }

// Limits cap archive expansion work.
type Limits struct {
	MaxDepth         int
	MaxEntryBytes    int64
	MaxExpandedBytes int64
	MaxFiles         int
}

func (l *Limits) withDefaults() {
	if l.MaxDepth <= 0 {
		l.MaxDepth = 4
	}
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = 50 * 1024 * 1024
	}
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = 200 * 1024 * 1024
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 1000
	}
}

func LooksLikeArchive(data []byte) bool {
	switch detect(data) {
	case kindZip, kindTar, kindGzip, kindBzip2:
		return true
	}
	return false
}

// Walk expands data into a flat list of inner entries.
func Walk(rootName string, data []byte, limits Limits) ([]Entry, error) {
	return WalkContext(context.Background(), rootName, data, limits)
}

// WalkContext is Walk with cancellation and deadline enforcement.
func WalkContext(ctx context.Context, rootName string, data []byte, limits Limits) ([]Entry, error) {
	if !LooksLikeArchive(data) {
		return nil, nil
	}
	limits.withDefaults()
	if rootName == "" {
		rootName = "<archive>"
	}
	state := &walkState{ctx: ctx, limits: limits}
	err := state.walk(rootName, data, 0)
	return state.entries, errors.Join(append(state.errs, err)...)
}

type walkState struct {
	ctx      context.Context
	limits   Limits
	entries  []Entry
	expanded int64
	errs     []error
	terminal bool
	rejected int
}

func (s *walkState) partial(kind, entry string, err error) {
	const maxRetainedErrors = 32
	if len(s.errs) < maxRetainedErrors {
		s.errs = append(s.errs, &PartialError{Kind: kind, Entry: entry, Err: err})
	}
}

func (s *walkState) stop(kind, entry string, err error) {
	if s.terminal {
		return
	}
	s.partial(kind, entry, err)
	s.terminal = true
}

func (s *walkState) rejectBudget(kind, entry string, err error) {
	s.partial(kind, entry, err)
	s.rejected++
	// A few oversized siblings must not hide later small files, but an archive
	// with millions of over-budget headers must not force an unbounded walk.
	if s.rejected >= 32 {
		s.terminal = true
	}
}

func (s *walkState) walk(name string, data []byte, depth int) error {
	if s.terminal {
		return nil
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if depth > s.limits.MaxDepth {
		s.partial("max-depth", name, fmt.Errorf("depth exceeds %d", s.limits.MaxDepth))
		return nil
	}
	switch detect(data) {
	case kindZip:
		return s.walkZip(name, data, depth)
	case kindTar:
		return s.walkTar(name, data, depth)
	case kindGzip:
		return s.walkGzip(name, data, depth)
	case kindBzip2:
		return s.walkBzip2(name, data, depth)
	default:
		s.appendEntry(name, data)
		return nil
	}
}

func (s *walkState) appendEntry(name string, data []byte) {
	if len(s.entries) >= s.limits.MaxFiles {
		s.stop("max-files", name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
		return
	}
	if int64(len(data)) > s.limits.MaxEntryBytes {
		s.partial("max-entry-bytes", name, fmt.Errorf("entry is %d bytes, limit %d", len(data), s.limits.MaxEntryBytes))
		return
	}
	if s.expanded+int64(len(data)) > s.limits.MaxExpandedBytes {
		s.rejectBudget("max-expanded-bytes", name, fmt.Errorf("expanded bytes exceed %d", s.limits.MaxExpandedBytes))
		return
	}
	s.expanded += int64(len(data))
	s.entries = append(s.entries, Entry{Path: name, Data: data})
}

func safeEntryName(name string) (string, bool) {
	// Archive names are slash-separated on every platform. Reject backslashes
	// too so Windows consumers cannot reinterpret a safe-looking provenance
	// path as an absolute or parent traversal.
	if strings.Contains(name, `\`) || strings.HasPrefix(name, "/") {
		return "", false
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if e := r.ctx.Err(); e != nil {
		return n, e
	}
	return n, err
}

func (s *walkState) walkZip(name string, data []byte, depth int) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	for _, f := range r.File {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			s.partial("symlink", f.Name, errors.New("symlink entries are not scanned"))
			continue
		}
		clean, ok := safeEntryName(f.Name)
		if !ok {
			s.partial("path", f.Name, errors.New("absolute or parent path rejected"))
			continue
		}
		if len(s.entries) >= s.limits.MaxFiles {
			s.stop("max-files", f.Name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		if f.UncompressedSize64 > uint64(s.limits.MaxEntryBytes) {
			s.partial("max-entry-bytes", f.Name, fmt.Errorf("declared size exceeds %d", s.limits.MaxEntryBytes))
			continue
		}
		if s.expanded+int64(f.UncompressedSize64) > s.limits.MaxExpandedBytes {
			s.rejectBudget("max-expanded-bytes", f.Name, fmt.Errorf("declared expansion exceeds %d", s.limits.MaxExpandedBytes))
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.partial("corrupt-entry", f.Name, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, rc}, s.limits.MaxEntryBytes+1))
		_ = rc.Close()
		if err != nil {
			s.partial("corrupt-entry", f.Name, err)
			continue
		}
		if int64(len(body)) > s.limits.MaxEntryBytes {
			s.partial("max-entry-bytes", f.Name, fmt.Errorf("entry exceeds %d", s.limits.MaxEntryBytes))
			continue
		}
		entryName := name + "!" + clean
		if err := s.walk(entryName, body, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (s *walkState) walkTar(name string, data []byte, depth int) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
		}
		if hdr.Typeflag != tar.TypeReg {
			if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
				s.partial("symlink", hdr.Name, errors.New("link entries are not scanned"))
			}
			continue
		}
		clean, ok := safeEntryName(hdr.Name)
		if !ok {
			s.partial("path", hdr.Name, errors.New("absolute or parent path rejected"))
			continue
		}
		if len(s.entries) >= s.limits.MaxFiles {
			s.stop("max-files", hdr.Name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		if hdr.Size > s.limits.MaxEntryBytes {
			s.partial("max-entry-bytes", hdr.Name, fmt.Errorf("declared size exceeds %d", s.limits.MaxEntryBytes))
			continue
		}
		if s.expanded+hdr.Size > s.limits.MaxExpandedBytes {
			s.rejectBudget("max-expanded-bytes", hdr.Name, fmt.Errorf("declared expansion exceeds %d", s.limits.MaxExpandedBytes))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, tr}, s.limits.MaxEntryBytes+1))
		if err != nil {
			s.partial("corrupt-entry", hdr.Name, err)
			continue
		}
		if int64(len(body)) > s.limits.MaxEntryBytes {
			s.partial("max-entry-bytes", hdr.Name, fmt.Errorf("entry exceeds %d", s.limits.MaxEntryBytes))
			continue
		}
		entryName := name + "!" + clean
		if err := s.walk(entryName, body, depth+1); err != nil {
			return err
		}
	}
}

func (s *walkState) walkGzip(name string, data []byte, depth int) error {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	defer r.Close()
	body, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, r}, s.limits.MaxEntryBytes+1))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return &PartialError{Kind: "corrupt-entry", Entry: name, Err: err}
	}
	if int64(len(body)) > s.limits.MaxEntryBytes {
		return &PartialError{Kind: "max-entry-bytes", Entry: name, Err: fmt.Errorf("entry exceeds %d", s.limits.MaxEntryBytes)}
	}
	innerName := strings.TrimSuffix(name, ".gz")
	if innerName == name {
		innerName = name + "!gz"
	}
	return s.walk(innerName, body, depth+1)
}

type kind int

const (
	kindNone kind = iota
	kindZip
	kindTar
	kindGzip
	kindBzip2
)

// detect inspects magic bytes to classify the chunk. Returns kindNone
// for anything that doesn't look like a recognised archive.
func detect(data []byte) kind {
	switch {
	case len(data) >= 4 && bytes.HasPrefix(data, []byte{0x50, 0x4b, 0x03, 0x04}):
		return kindZip
	case len(data) >= 4 && bytes.HasPrefix(data, []byte{0x50, 0x4b, 0x05, 0x06}):
		// Empty zip — no entries to walk, but still a zip.
		return kindZip
	case len(data) >= 2 && bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return kindGzip
	case len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")):
		// POSIX tar magic at offset 257.
		return kindTar
	case len(data) >= 3 && bytes.HasPrefix(data, []byte{0x42, 0x5a, 0x68}):
		// bzip2: "BZh" header.
		return kindBzip2
	}
	return kindNone
}

func (s *walkState) walkBzip2(name string, data []byte, depth int) error {
	body, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, bzip2.NewReader(bytes.NewReader(data))}, s.limits.MaxEntryBytes+1))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return &PartialError{Kind: "corrupt-entry", Entry: name, Err: err}
	}
	if int64(len(body)) > s.limits.MaxEntryBytes {
		return &PartialError{Kind: "max-entry-bytes", Entry: name, Err: fmt.Errorf("entry exceeds %d", s.limits.MaxEntryBytes)}
	}
	innerName := strings.TrimSuffix(name, ".bz2")
	if innerName == name {
		innerName = name + "!bz2"
	}
	return s.walk(innerName, body, depth+1)
}
