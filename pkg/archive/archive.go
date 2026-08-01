// Package archive expands zip, tar, gzip, and bzip2 payloads into leaf entries.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

// SpillThreshold is the largest archive value retained in memory by the
// streaming API. Larger inputs and expanded entries use 0600 temporary files.
const SpillThreshold int64 = 16 << 20

const (
	maxRetainedErrors    = 32
	maxArchiveHeaders    = 10_000
	maxZipDirectoryBytes = 16 << 20
	maxTarMetadataBytes  = 1 << 20
)

var spoolCopyBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, 64<<10)
	return &buffer
}}

// Entry is one expanded file from inside an archive.
//
// Deprecated for large inputs: Walk and WalkContext retain every Entry.Data
// until the walk completes. Use WalkStreamContext for bounded-memory scans.
type Entry struct {
	Path string
	Data []byte
}

// StreamEntry is valid only for the duration of a WalkStreamContext callback.
// The reader starts at byte zero and is backed by memory or a temporary file.
type StreamEntry struct {
	Path   string
	Size   int64
	Reader io.Reader
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

// Limits cap archive expansion work. MaxFiles caps emitted leaves; readers
// independently reject archives above the package-level physical-header and
// metadata ceilings before the standard-library parsers allocate them.
type Limits struct {
	MaxDepth         int
	MaxInputBytes    int64
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
	if l.MaxInputBytes <= 0 {
		l.MaxInputBytes = 50 * 1024 * 1024
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

// WalkContext is the compatibility, collecting form of WalkStreamContext.
// Its []byte input and []Entry result necessarily remain resident in memory.
func WalkContext(ctx context.Context, rootName string, data []byte, limits Limits) ([]Entry, error) {
	if !LooksLikeArchive(data) {
		return nil, nil
	}
	var entries []Entry
	err := WalkStreamContext(ctx, rootName, bytes.NewReader(data), int64(len(data)), limits, func(entry StreamEntry) error {
		body, err := io.ReadAll(entry.Reader)
		if err != nil {
			return err
		}
		entries = append(entries, Entry{Path: entry.Path, Data: body})
		return nil
	})
	return entries, err
}

// WalkStreamContext validates and expands one archive, invoking visit in
// stable archive order only after each leaf has reached EOF and passed its
// format checksum. Large values spill to 0600 temporary files, all of which
// are removed before this function returns.
func WalkStreamContext(ctx context.Context, rootName string, input io.Reader, size int64, limits Limits, visit func(StreamEntry) error) error {
	return walkStreamContext(ctx, rootName, input, size, limits, visit, spoolOptions{threshold: SpillThreshold})
}

// WithSpoolContext consumes and validates exactly size bytes before invoking
// fn with a reader at byte zero. Values over limit fail without invoking fn;
// values above SpillThreshold are file-backed and cleaned on every path.
func WithSpoolContext(ctx context.Context, input io.Reader, size, limit int64, fn func(io.Reader) error) error {
	if input == nil || fn == nil {
		return errors.New("archive: nil spool input or callback")
	}
	return withSpool(ctx, input, size, limit, spoolOptions{threshold: SpillThreshold}, func(value *spool) error {
		return fn(value.reader())
	})
}

type spoolOptions struct {
	threshold int64
	tempDir   string
}

func walkStreamContext(ctx context.Context, rootName string, input io.Reader, size int64, limits Limits, visit func(StreamEntry) error, opts spoolOptions) error {
	if input == nil || visit == nil {
		return errors.New("archive: nil input or callback")
	}
	limits.withDefaults()
	if rootName == "" {
		rootName = "<archive>"
	}
	err := withSpool(ctx, input, size, limits.MaxInputBytes, opts, func(root *spool) error {
		kind, err := root.kind()
		if err != nil {
			return &PartialError{Kind: "corrupt-archive", Entry: rootName, Err: err}
		}
		if kind == kindNone {
			return nil
		}
		state := &walkState{ctx: ctx, limits: limits, visit: visit, spool: opts}
		err = state.walk(rootName, root, 0)
		return errors.Join(append(state.errs, err)...)
	})
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var partial *PartialError
	if errors.As(err, &partial) {
		return err
	}
	var tooLarge *spoolLimitError
	if errors.As(err, &tooLarge) {
		return &PartialError{Kind: "max-input-bytes", Entry: rootName, Err: err}
	}
	return &PartialError{Kind: "corrupt-archive", Entry: rootName, Err: err}
}

type walkState struct {
	ctx      context.Context
	limits   Limits
	visit    func(StreamEntry) error
	spool    spoolOptions
	expanded int64
	files    int
	headers  int
	errs     []error
	terminal bool
	rejected int
}

func (s *walkState) partial(kind, entry string, err error) {
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
	// with many over-budget headers must not force an unbounded walk.
	if s.rejected >= maxRetainedErrors {
		s.terminal = true
	}
}

func (s *walkState) walk(name string, data *spool, depth int) error {
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
	kind, err := data.kind()
	if err != nil {
		return &PartialError{Kind: "corrupt-entry", Entry: name, Err: err}
	}
	switch kind {
	case kindZip:
		return s.walkZip(name, data, depth)
	case kindTar:
		return s.walkTar(name, data, depth)
	case kindGzip:
		return s.walkGzip(name, data, depth)
	case kindBzip2:
		return s.walkBzip2(name, data, depth)
	default:
		return s.emitEntry(name, data)
	}
}

func (s *walkState) emitEntry(name string, data *spool) error {
	if s.files >= s.limits.MaxFiles {
		s.stop("max-files", name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
		return nil
	}
	s.files++
	return s.visit(StreamEntry{Path: name, Size: data.size, Reader: data.reader()})
}

func safeEntryName(name string) (string, bool) {
	// Archive names are slash-separated on every platform. Reject every parent
	// component and Windows volume spelling too, even on non-Windows hosts.
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") {
		return "", false
	}
	if len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) {
		return "", false
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", false
		}
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
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

func (s *walkState) expandedSpool(name string, input io.Reader, declared int64) (*spool, bool, error) {
	if declared > s.limits.MaxEntryBytes {
		s.partial("max-entry-bytes", name, fmt.Errorf("declared size exceeds %d", s.limits.MaxEntryBytes))
		return nil, false, nil
	}
	remaining := s.limits.MaxExpandedBytes - s.expanded
	if declared >= 0 && declared > remaining {
		s.rejectBudget("max-expanded-bytes", name, fmt.Errorf("declared expansion exceeds %d", s.limits.MaxExpandedBytes))
		return nil, false, nil
	}
	limit := s.limits.MaxEntryBytes
	limitKind := "max-entry-bytes"
	if remaining < limit {
		limit = remaining
		limitKind = "max-expanded-bytes"
	}
	value, err := spoolFromReader(s.ctx, input, declared, limit, s.spool)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		var tooLarge *spoolLimitError
		if errors.As(err, &tooLarge) {
			s.rejectBudget(limitKind, name, fmt.Errorf("expanded bytes exceed %d", limit))
			return nil, false, nil
		}
		s.partial("corrupt-entry", name, err)
		return nil, false, nil
	}
	s.expanded += value.size
	return value, true, nil
}

func (s *walkState) walkZip(name string, data *spool, depth int) error {
	remaining := maxArchiveHeaders - s.headers
	count, err := preflightZip(s.ctx, data.readerAt(), data.size, remaining)
	if err != nil {
		var headerLimit *zipHeaderLimitError
		if errors.As(err, &headerLimit) {
			s.stop(headerLimit.kind, name, headerLimit)
			return nil
		}
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	s.headers += count
	r, err := zip.NewReader(data.readerAt(), data.size)
	if err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	if len(r.File) != count {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: fmt.Errorf("central directory count changed from %d to %d", count, len(r.File))}
	}
	for _, file := range r.File {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		mode := file.Mode()
		if mode.IsDir() {
			continue
		}
		if mode&os.ModeSymlink != 0 {
			s.partial("symlink", file.Name, errors.New("symlink entries are not scanned"))
			continue
		}
		if mode&os.ModeType != 0 {
			s.partial("special-file", file.Name, errors.New("non-regular entries are not scanned"))
			continue
		}
		clean, ok := safeEntryName(file.Name)
		if !ok {
			s.partial("path", file.Name, errors.New("unsafe archive path rejected"))
			continue
		}
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", file.Name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		if file.UncompressedSize64 > uint64(^uint64(0)>>1) {
			s.partial("max-entry-bytes", file.Name, errors.New("declared size overflows int64"))
			continue
		}
		rc, err := file.Open()
		if err != nil {
			s.partial("corrupt-entry", file.Name, err)
			continue
		}
		value, accepted, copyErr := s.expandedSpool(file.Name, rc, int64(file.UncompressedSize64))
		closeErr := rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if !accepted {
			continue
		}
		entryName := name + "!" + clean
		if closeErr != nil {
			s.partial("corrupt-entry", file.Name, closeErr)
			if cleanupErr := value.close(); cleanupErr != nil {
				s.partial("cleanup", entryName, cleanupErr)
			}
			continue
		}
		walkErr := s.walk(entryName, value, depth+1)
		cleanupErr := value.close()
		if cleanupErr != nil {
			s.partial("cleanup", entryName, cleanupErr)
		}
		if walkErr != nil {
			return walkErr
		}
	}
	return nil
}

func (s *walkState) walkTar(name string, data *spool, depth int) error {
	count, err := preflightTar(s.ctx, data.readerAt(), data.size, maxArchiveHeaders-s.headers)
	if err != nil {
		var limit *tarPreflightLimitError
		if errors.As(err, &limit) {
			s.stop(limit.kind, name, limit)
			return nil
		}
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	s.headers += count
	// tar.Reader discards an unread body inside Next. Keep that implicit read
	// context-aware too, especially after rejecting an oversized header.
	return s.walkTarReader(name, contextReader{ctx: s.ctx, r: data.reader()}, depth)
}

func (s *walkState) walkTarReader(name string, input io.Reader, depth int) error {
	reader := tar.NewReader(input)
	for {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			s.partial("symlink", header.Name, errors.New("link entries are not scanned"))
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		clean, ok := safeEntryName(header.Name)
		if !ok {
			s.partial("path", header.Name, errors.New("unsafe archive path rejected"))
			continue
		}
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", header.Name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		value, accepted, copyErr := s.expandedSpool(header.Name, reader, header.Size)
		if copyErr != nil {
			return copyErr
		}
		if !accepted {
			continue
		}
		entryName := name + "!" + clean
		walkErr := s.walk(entryName, value, depth+1)
		cleanupErr := value.close()
		if cleanupErr != nil {
			s.partial("cleanup", entryName, cleanupErr)
		}
		if walkErr != nil {
			return walkErr
		}
	}
}

func (s *walkState) walkGzip(name string, data *spool, depth int) error {
	reader, err := gzip.NewReader(data.reader())
	if err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	value, accepted, copyErr := s.expandedSpool(name, reader, -1)
	closeErr := reader.Close()
	if copyErr != nil {
		return copyErr
	}
	if !accepted {
		return nil
	}
	if closeErr != nil {
		if cleanupErr := value.close(); cleanupErr != nil {
			s.partial("cleanup", name, cleanupErr)
		}
		return &PartialError{Kind: "corrupt-entry", Entry: name, Err: closeErr}
	}
	innerName := strings.TrimSuffix(name, ".gz")
	if innerName == name {
		innerName = name + "!gz"
	}
	walkErr := s.walk(innerName, value, depth+1)
	cleanupErr := value.close()
	if cleanupErr != nil {
		s.partial("cleanup", innerName, cleanupErr)
	}
	return walkErr
}

func (s *walkState) walkBzip2(name string, data *spool, depth int) error {
	value, accepted, err := s.expandedSpool(name, bzip2.NewReader(data.reader()), -1)
	if err != nil || !accepted {
		return err
	}
	innerName := strings.TrimSuffix(name, ".bz2")
	if innerName == name {
		innerName = name + "!bz2"
	}
	walkErr := s.walk(innerName, value, depth+1)
	cleanupErr := value.close()
	if cleanupErr != nil {
		s.partial("cleanup", innerName, cleanupErr)
	}
	return walkErr
}

type tarPreflightLimitError struct {
	kind         string
	value, limit int64
}

func (e *tarPreflightLimitError) Error() string {
	return fmt.Sprintf("TAR %s %d exceeds %d", e.kind, e.value, e.limit)
}

// preflightTar walks physical 512-byte records without interpreting names or
// PAX key/value data. This bounds the metadata archive/tar would otherwise
// parse and allocate before returning a logical Header.
func preflightTar(ctx context.Context, reader io.ReaderAt, size int64, maxHeaders int) (int, error) {
	if size < 0 || maxHeaders < 0 {
		return 0, errors.New("tar: invalid size or header limit")
	}
	var (
		offset        int64
		metadataBytes int64
		headers       int
	)
	for offset < size {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if size-offset < 512 {
			return 0, errors.New("tar: truncated physical header")
		}
		var block [512]byte
		if _, err := reader.ReadAt(block[:], offset); err != nil {
			return 0, err
		}
		zero := true
		for _, value := range block {
			if value != 0 {
				zero = false
				break
			}
		}
		if zero {
			return headers, nil
		}
		headers++
		if headers > maxHeaders {
			return 0, &tarPreflightLimitError{kind: "max-headers", value: int64(headers), limit: int64(maxHeaders)}
		}
		bodySize, err := parseTarSize(block[124:136])
		if err != nil {
			return 0, err
		}
		switch block[156] {
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			if bodySize > maxTarMetadataBytes-metadataBytes {
				return 0, &tarPreflightLimitError{kind: "metadata-bytes", value: metadataBytes + bodySize, limit: maxTarMetadataBytes}
			}
			metadataBytes += bodySize
		case tar.TypeGNUSparse:
			return 0, errors.New("tar: GNU sparse metadata is not supported")
		}
		if bodySize > int64(^uint64(0)>>1)-511 {
			return 0, errors.New("tar: physical entry size overflows int64")
		}
		padded := (bodySize + 511) &^ 511
		if padded > size-offset-512 {
			return 0, errors.New("tar: physical entry exceeds archive")
		}
		offset += 512 + padded
	}
	return headers, nil
}

func parseTarSize(field []byte) (int64, error) {
	if len(field) == 0 {
		return 0, errors.New("tar: empty size field")
	}
	if field[0]&0x80 != 0 {
		if field[0]&0x40 != 0 {
			return 0, errors.New("tar: negative size")
		}
		var value uint64
		for i, current := range field {
			if i == 0 {
				current &= 0x7f
			}
			if value > (^uint64(0)-uint64(current))/256 {
				return 0, errors.New("tar: size field overflows uint64")
			}
			value = value*256 + uint64(current)
		}
		if value > uint64(^uint64(0)>>1) {
			return 0, errors.New("tar: size field overflows int64")
		}
		return int64(value), nil
	}
	trimmed := strings.Trim(string(field), " \x00")
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(trimmed, 8, 63)
	if err != nil {
		return 0, fmt.Errorf("tar: invalid size field: %w", err)
	}
	return int64(value), nil
}

type kind int

const (
	kindNone kind = iota
	kindZip
	kindTar
	kindGzip
	kindBzip2
)

// detect inspects magic bytes to classify the chunk. Returns kindNone for
// anything that does not look like a recognised archive.
func detect(data []byte) kind {
	switch {
	case len(data) >= 4 && bytes.HasPrefix(data, []byte{0x50, 0x4b, 0x03, 0x04}):
		return kindZip
	case len(data) >= 4 && bytes.HasPrefix(data, []byte{0x50, 0x4b, 0x05, 0x06}):
		return kindZip
	case len(data) >= 2 && bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return kindGzip
	case len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")):
		return kindTar
	case len(data) >= 3 && bytes.HasPrefix(data, []byte{0x42, 0x5a, 0x68}):
		return kindBzip2
	}
	return kindNone
}

type spool struct {
	opts spoolOptions
	mem  bytes.Buffer
	file *os.File
	path string
	size int64
}

func spoolFromReader(ctx context.Context, input io.Reader, expected, limit int64, opts spoolOptions) (_ *spool, err error) {
	if input == nil || expected < -1 || limit < 0 {
		return nil, errors.New("archive: invalid spool bounds")
	}
	if expected > limit {
		return nil, &spoolLimitError{limit: limit}
	}
	if opts.threshold <= 0 {
		opts.threshold = SpillThreshold
	}
	value := &spool{opts: opts}
	defer func() {
		if err != nil {
			err = errors.Join(err, value.close())
		}
	}()
	if expected > opts.threshold {
		if err := value.spill(); err != nil {
			return nil, err
		}
	}
	reader := io.LimitReader(contextReader{ctx: ctx, r: input}, limit+1)
	buffer := spoolCopyBufferPool.Get().(*[]byte)
	written, err := io.CopyBuffer(value, reader, *buffer)
	spoolCopyBufferPool.Put(buffer)
	if err != nil {
		return nil, err
	}
	if written > limit {
		return nil, &spoolLimitError{limit: limit}
	}
	if expected >= 0 && written != expected {
		return nil, fmt.Errorf("archive: unexpected size %d, want %d", written, expected)
	}
	return value, nil
}

func withSpool(ctx context.Context, input io.Reader, expected, limit int64, opts spoolOptions, fn func(*spool) error) (err error) {
	value, err := spoolFromReader(ctx, input, expected, limit, opts)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, value.close()) }()
	return fn(value)
}

func (s *spool) Write(data []byte) (int, error) {
	if s.file == nil && s.size+int64(len(data)) > s.opts.threshold {
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	var (
		n   int
		err error
	)
	if s.file != nil {
		n, err = s.file.Write(data)
	} else {
		n, err = s.mem.Write(data)
	}
	s.size += int64(n)
	return n, err
}

func (s *spool) spill() error {
	if s.file != nil {
		return nil
	}
	file, err := os.CreateTemp(s.opts.tempDir, "pleno-dlp-archive-*")
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return err
	}
	if s.mem.Len() > 0 {
		if _, err := file.Write(s.mem.Bytes()); err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			return err
		}
	}
	s.file = file
	s.path = file.Name()
	s.mem = bytes.Buffer{}
	return nil
}

func (s *spool) reader() io.Reader {
	if s.file != nil {
		return io.NewSectionReader(s.file, 0, s.size)
	}
	return bytes.NewReader(s.mem.Bytes())
}

func (s *spool) readerAt() io.ReaderAt {
	if s.file != nil {
		return s.file
	}
	return bytes.NewReader(s.mem.Bytes())
}

func (s *spool) kind() (kind, error) {
	length := s.size
	if length > 512 {
		length = 512
	}
	prefix := make([]byte, length)
	if length > 0 {
		n, err := s.readerAt().ReadAt(prefix, 0)
		if err != nil && err != io.EOF {
			return kindNone, err
		}
		prefix = prefix[:n]
	}
	return detect(prefix), nil
}

func (s *spool) close() error {
	if s == nil || s.file == nil {
		return nil
	}
	closeErr := s.file.Close()
	removeErr := os.Remove(s.path)
	s.file = nil
	s.path = ""
	return errors.Join(closeErr, removeErr)
}

type spoolLimitError struct{ limit int64 }

func (e *spoolLimitError) Error() string {
	return fmt.Sprintf("archive: value exceeds %d-byte limit", e.limit)
}

type zipHeaderLimitError struct {
	kind  string
	count uint64
	limit uint64
}

func (e *zipHeaderLimitError) Error() string {
	return fmt.Sprintf("ZIP %s %d exceeds %d", e.kind, e.count, e.limit)
}

func preflightZip(ctx context.Context, reader io.ReaderAt, size int64, maxHeaders int) (int, error) {
	if size < 22 || maxHeaders < 0 {
		return 0, errors.New("zip: invalid size or header limit")
	}
	tailSize := size
	if tailSize > 22+65535 {
		tailSize = 22 + 65535
	}
	tail := make([]byte, int(tailSize))
	if _, err := reader.ReadAt(tail, size-tailSize); err != nil && err != io.EOF {
		return 0, err
	}
	eocd := -1
	for offset := len(tail) - 22; offset >= 0; offset-- {
		if binary.LittleEndian.Uint32(tail[offset:offset+4]) != 0x06054b50 {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[offset+20 : offset+22]))
		if offset+22+commentLen <= len(tail) {
			eocd = offset
			break
		}
	}
	if eocd < 0 {
		return 0, errors.New("zip: end of central directory not found")
	}
	absEOCD := size - tailSize + int64(eocd)
	disk := binary.LittleEndian.Uint16(tail[eocd+4 : eocd+6])
	dirDisk := binary.LittleEndian.Uint16(tail[eocd+6 : eocd+8])
	recordsDisk := uint64(binary.LittleEndian.Uint16(tail[eocd+8 : eocd+10]))
	records := uint64(binary.LittleEndian.Uint16(tail[eocd+10 : eocd+12]))
	directorySize := uint64(binary.LittleEndian.Uint32(tail[eocd+12 : eocd+16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(tail[eocd+16 : eocd+20]))
	directoryEnd := absEOCD
	if records == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		var err error
		recordsDisk, records, directorySize, directoryOffset, directoryEnd, err = readZip64End(reader, absEOCD)
		if err != nil {
			return 0, err
		}
		disk, dirDisk = 0, 0
	}
	if disk != 0 || dirDisk != 0 || recordsDisk != records {
		return 0, errors.New("zip: multi-disk archives are not supported")
	}
	if directorySize > maxZipDirectoryBytes {
		return 0, &zipHeaderLimitError{kind: "central-directory-bytes", count: directorySize, limit: maxZipDirectoryBytes}
	}
	if directorySize > uint64(directoryEnd) || directoryOffset > uint64(size) {
		return 0, errors.New("zip: central directory is outside archive")
	}
	count, err := countZipDirectory(ctx, reader, directoryEnd-int64(directorySize), int64(directorySize), maxHeaders)
	if err != nil {
		return 0, err
	}
	if uint64(count) != records {
		return 0, errors.New("zip: central directory record count mismatch")
	}
	return count, nil
}

func readZip64End(reader io.ReaderAt, eocdOffset int64) (recordsDisk, records, directorySize, directoryOffset uint64, directoryEnd int64, err error) {
	if eocdOffset < 20 {
		err = errors.New("zip: ZIP64 locator missing")
		return
	}
	locator := make([]byte, 20)
	if _, err = reader.ReadAt(locator, eocdOffset-20); err != nil {
		return
	}
	if binary.LittleEndian.Uint32(locator[:4]) != 0x07064b50 || binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		err = errors.New("zip: invalid ZIP64 locator")
		return
	}
	directoryEnd = int64(binary.LittleEndian.Uint64(locator[8:16]))
	if directoryEnd < 0 || directoryEnd > eocdOffset-56 {
		err = errors.New("zip: ZIP64 end record is outside archive")
		return
	}
	header := make([]byte, 56)
	if _, err = reader.ReadAt(header, directoryEnd); err != nil {
		return
	}
	if binary.LittleEndian.Uint32(header[:4]) != 0x06064b50 || binary.LittleEndian.Uint64(header[4:12]) < 44 {
		err = errors.New("zip: invalid ZIP64 end record")
		return
	}
	if binary.LittleEndian.Uint32(header[16:20]) != 0 || binary.LittleEndian.Uint32(header[20:24]) != 0 {
		err = errors.New("zip: multi-disk ZIP64 archives are not supported")
		return
	}
	recordsDisk = binary.LittleEndian.Uint64(header[24:32])
	records = binary.LittleEndian.Uint64(header[32:40])
	directorySize = binary.LittleEndian.Uint64(header[40:48])
	directoryOffset = binary.LittleEndian.Uint64(header[48:56])
	return
}

func countZipDirectory(ctx context.Context, reader io.ReaderAt, offset, size int64, maxHeaders int) (int, error) {
	if offset < 0 || size < 0 {
		return 0, errors.New("zip: invalid central directory bounds")
	}
	end := offset + size
	if end < offset {
		return 0, errors.New("zip: central directory size overflow")
	}
	count := 0
	for offset < end {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if end-offset < 46 {
			return 0, errors.New("zip: truncated central directory header")
		}
		header := make([]byte, 46)
		if _, err := reader.ReadAt(header, offset); err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint32(header[:4]) != 0x02014b50 {
			return 0, errors.New("zip: invalid central directory signature")
		}
		count++
		if count > maxHeaders {
			return 0, &zipHeaderLimitError{kind: "max-headers", count: uint64(count), limit: uint64(maxHeaders)}
		}
		nameLen := int64(binary.LittleEndian.Uint16(header[28:30]))
		extraLen := int64(binary.LittleEndian.Uint16(header[30:32]))
		commentLen := int64(binary.LittleEndian.Uint16(header[32:34]))
		step := int64(46) + nameLen + extraLen + commentLen
		if step > end-offset {
			return 0, errors.New("zip: central directory field exceeds declared size")
		}
		offset += step
	}
	return count, nil
}
