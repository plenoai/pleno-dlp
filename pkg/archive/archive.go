// Package archive expands zip, tar, and gzip payloads into leaf entries.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Entry is one expanded file from inside an archive.
type Entry struct {
	Path string
	Data []byte
}

// Limits cap archive expansion work.
type Limits struct {
	MaxDepth         int
	MaxEntryBytes    int64
	MaxExpandedBytes int64
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
}

func LooksLikeArchive(data []byte) bool {
	switch detect(data) {
	case kindZip, kindTar, kindGzip:
		return true
	}
	return false
}

// Walk expands data into a flat list of inner entries.
func Walk(rootName string, data []byte, limits Limits) ([]Entry, error) {
	if !LooksLikeArchive(data) {
		return nil, nil
	}
	limits.withDefaults()
	if rootName == "" {
		rootName = "<archive>"
	}
	state := &walkState{limits: limits}
	if err := state.walk(rootName, data, 0); err != nil {
		return state.entries, err
	}
	return state.entries, nil
}

type walkState struct {
	limits   Limits
	entries  []Entry
	expanded int64
}

func (s *walkState) walk(name string, data []byte, depth int) error {
	if depth > s.limits.MaxDepth {
		return nil
	}
	switch detect(data) {
	case kindZip:
		return s.walkZip(name, data, depth)
	case kindTar:
		return s.walkTar(name, data, depth)
	case kindGzip:
		return s.walkGzip(name, data, depth)
	default:
		s.appendEntry(name, data)
		return nil
	}
}

func (s *walkState) appendEntry(name string, data []byte) {
	if int64(len(data)) > s.limits.MaxEntryBytes {
		return
	}
	if s.expanded+int64(len(data)) > s.limits.MaxExpandedBytes {
		return
	}
	s.expanded += int64(len(data))
	s.entries = append(s.entries, Entry{Path: name, Data: data})
}

func (s *walkState) walkZip(name string, data []byte, depth int) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("zip(%s): %w", name, err)
	}
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > uint64(s.limits.MaxEntryBytes) {
			continue
		}
		if s.expanded+int64(f.UncompressedSize64) > s.limits.MaxExpandedBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, s.limits.MaxEntryBytes+1))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if int64(len(body)) > s.limits.MaxEntryBytes {
			continue
		}
		entryName := name + "!" + path.Clean(f.Name)
		if err := s.walk(entryName, body, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (s *walkState) walkTar(name string, data []byte, depth int) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar(%s): %w", name, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > s.limits.MaxEntryBytes {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, s.limits.MaxEntryBytes+1))
		if err != nil {
			continue
		}
		if int64(len(body)) > s.limits.MaxEntryBytes {
			continue
		}
		entryName := name + "!" + path.Clean(hdr.Name)
		if err := s.walk(entryName, body, depth+1); err != nil {
			return err
		}
	}
}

func (s *walkState) walkGzip(name string, data []byte, depth int) error {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gzip(%s): %w", name, err)
	}
	defer r.Close()
	body, err := io.ReadAll(io.LimitReader(r, s.limits.MaxEntryBytes+1))
	if err != nil {
		return fmt.Errorf("gzip(%s): read: %w", name, err)
	}
	if int64(len(body)) > s.limits.MaxEntryBytes {
		return errors.New("gzip: entry exceeds MaxEntryBytes")
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
	}
	return kindNone
}
