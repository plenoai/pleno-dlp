// Package archive expands a byte slice that looks like a container file
// (zip, tar, tar.gz, plain gzip) into its inner entries so detectors run
// against the contents instead of the compressed envelope.
//
// Walk is the single entry point: it inspects magic bytes, dispatches to
// the right reader, and returns a flat list of Entry{Path, Data}. Nested
// archives unwind recursively up to MaxDepth — anything deeper than that
// is dropped to keep zip-bombs from exhausting memory in CI runners.
//
// Per-entry size and total expansion-ratio caps are enforced to defeat
// the same DoS class. Defaults are conservative; callers needing to scan
// genuinely large fixtures can pass a larger Limits explicitly.
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

// Entry is one expanded file from inside an archive. Path is the
// composed inner path (e.g. "outer.zip!inner.tar.gz!leak.txt"); the "!"
// separator mirrors how Java/Maven name nested artifacts and gives a
// readable trail when a finding is reported.
type Entry struct {
	Path string
	Data []byte
}

// Limits caps the work an archive walk is allowed to do. Anything zero
// is replaced by the default at Walk time so callers can pass a partial
// struct without surprise.
type Limits struct {
	// MaxDepth is the recursion cap for nested archives. Default 4.
	MaxDepth int
	// MaxEntryBytes caps the size of any single uncompressed entry.
	// Default 50 MiB — large enough for real test fixtures, small
	// enough to refuse memory pressure from a 4 GiB zip bomb.
	MaxEntryBytes int64
	// MaxExpandedBytes caps the total uncompressed size across every
	// entry combined. Default 200 MiB. Trips the zip-bomb defence
	// when a small archive expands to GiB.
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

// LooksLikeArchive returns true when data's first bytes match a known
// container magic. Cheap to call; safe to use as a hot-path gate before
// invoking Walk.
func LooksLikeArchive(data []byte) bool {
	switch detect(data) {
	case kindZip, kindTar, kindGzip:
		return true
	}
	return false
}

// Walk expands data into a flat list of inner entries. Returns an empty
// slice (and nil error) when data isn't a recognised archive — Walk is
// safe to call on every chunk, including ones that aren't archives.
//
// rootName is used to compose Entry.Path; pass the on-disk filename or
// other source-meaningful identifier. An empty string is replaced with
// "<archive>" so output never contains a literal empty path component.
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
		// Quietly drop entries past the cap. An error here would fail
		// the entire scan when a single deeply-nested archive shows
		// up in real corpora; that's worse than missing the leaf.
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
		// Bottom of recursion: a non-archive blob is emitted as a leaf
		// entry. Top-level non-archive input bypasses Walk entirely
		// (Walk callers gate on LooksLikeArchive), so the leaf path
		// here is reached only via recursion.
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
		// Refuse expansion-ratio attacks. UncompressedSize64 is what
		// the archive claims; trusting a 4 GiB claim would mean
		// allocating a 4 GiB buffer to read into.
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
		// One byte over the cap means the actual content exceeded
		// what UncompressedSize64 promised — refuse silently.
		if int64(len(body)) > s.limits.MaxEntryBytes {
			continue
		}
		entryName := name + "!" + path.Clean(f.Name)
		// Recurse instead of emitting unconditionally — nested zips,
		// jars and tar.gz files are common in real corpora.
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
		// tar.Reader normalizes the legacy TypeRegA ('\x00') to TypeReg on
		// read, so checking TypeReg alone covers old GNU/V7 archives too.
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

// kind is the internal classification of a byte slice.
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
