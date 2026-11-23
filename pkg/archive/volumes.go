package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Multi-volume archives arrive as sibling files or objects, one per volume.
// Sources group the siblings with ParseVolumeName/VolumeName and hand the
// archive walker one logical stream built by JoinVolumes, so members that
// cross a volume boundary are decoded instead of reported as split-volume
// gaps. Two schemes are recognized:
//
//   - VolumeEgg: ALZip split archives "<base>.vol1.egg", "<base>.vol2.egg",
//     ... Every volume repeats the EGG header with a split extra field
//     (previous and next volume header ids); continuation headers are
//     stripped and the chain of ids must link, so an unrelated or reordered
//     file is never spliced in.
//   - VolumeBytes: byte-level splits "<base>.<ext>.001", ".002", ... of a
//     container this package expands (zip, tar, gzip, bzip2, xz, zstd, egg),
//     as written by 7-Zip, HJSplit, or split(1) with numeric suffixes. The
//     volumes are concatenated verbatim.
//
// Spanned PKZIP sets (".z01" ... ".zip") record per-disk offsets in the
// central directory and need a disk-aware reader; they stay out of scope.

// VolumeScheme names a multi-volume naming and joining convention.
type VolumeScheme int

const (
	VolumeNone VolumeScheme = iota
	VolumeEgg
	VolumeBytes
)

// MaxVolumes bounds how many sibling volumes one logical archive may span.
const MaxVolumes = 999

var (
	eggVolumeName   = regexp.MustCompile(`(?i)^(.+)\.vol([1-9][0-9]{0,2})\.egg$`)
	bytesVolumeName = regexp.MustCompile(`(?i)^(.+\.(?:zip|jar|tar|tgz|gz|bz2|tbz2|xz|txz|zst|egg))\.([0-9]{3})$`)
)

// VolumeID identifies one volume of a multi-volume archive by name.
type VolumeID struct {
	Scheme VolumeScheme
	Base   string // name without the volume suffix; shared by all siblings
	Index  int    // 1-based volume number
	width  int    // digit width of a VolumeBytes suffix (".001" -> 3)
	suffix string // original-case suffix spelling for VolumeEgg (".egg")
}

// ParseVolumeName reports whether name (a base name or a full path/key)
// looks like one volume of a multi-volume archive.
func ParseVolumeName(name string) (VolumeID, bool) {
	if m := eggVolumeName.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[2])
		volPos := len(m[1])
		return VolumeID{Scheme: VolumeEgg, Base: m[1], Index: n, suffix: name[volPos : volPos+4]}, true
	}
	if m := bytesVolumeName.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[2])
		if n < 1 {
			return VolumeID{}, false
		}
		return VolumeID{Scheme: VolumeBytes, Base: m[1], Index: n, width: len(m[2])}, true
	}
	return VolumeID{}, false
}

// Sibling returns the name of volume index of the same set, preserving the
// spelling of id's own name.
func (id VolumeID) Sibling(index int) string {
	switch id.Scheme {
	case VolumeEgg:
		ext := ".egg"
		if strings.HasPrefix(id.suffix, ".VOL") {
			ext = ".EGG"
		}
		return fmt.Sprintf("%s%s%d%s", id.Base, id.suffix, index, ext)
	case VolumeBytes:
		return fmt.Sprintf("%s.%0*d", id.Base, id.width, index)
	}
	return ""
}

// Volume is one sibling volume's bytes.
type Volume struct {
	R    io.ReaderAt
	Size int64
}

// ErrVolumeChain reports volumes that do not form one archive: a missing
// volume, a reordered or unrelated file, or a total above the budget.
var ErrVolumeChain = errors.New("volumes do not form one archive")

// JoinVolumes returns one logical reader over vols, which must be volumes
// 1..n of the same set in order. The total logical size may not exceed
// maxTotal. For VolumeEgg it returns the longest prefix of vols whose split
// ids link (at least the first volume); count reports how many volumes were
// joined so callers can scan the remainder separately.
func JoinVolumes(scheme VolumeScheme, vols []Volume, maxTotal int64) (r io.ReaderAt, size int64, count int, err error) {
	if len(vols) == 0 || len(vols) > MaxVolumes {
		return nil, 0, 0, fmt.Errorf("%w: %d volumes", ErrVolumeChain, len(vols))
	}
	parts := make([]readerPart, 0, len(vols))
	switch scheme {
	case VolumeBytes:
		for _, v := range vols {
			parts = append(parts, readerPart{r: v.R, off: 0, size: v.Size})
		}
	case VolumeEgg:
		var prevID uint32
		for i, v := range vols {
			id, prev, next, body, err := eggVolumeHeader(v.R, v.Size)
			if err != nil {
				if i == 0 {
					return nil, 0, 0, fmt.Errorf("%w: %v", ErrVolumeChain, err)
				}
				break
			}
			if i == 0 {
				if prev != 0 || next == 0 {
					return nil, 0, 0, fmt.Errorf("%w: first EGG volume is not the head of a split set", ErrVolumeChain)
				}
				// The head keeps its header: it carries the archive-level
				// extras (solid, encryption) the parser needs.
				parts = append(parts, readerPart{r: v.R, size: v.Size})
			} else {
				if prev != prevID {
					break
				}
				parts = append(parts, readerPart{r: v.R, off: body, size: v.Size - body})
			}
			prevID = id
			if next == 0 {
				break
			}
		}
	default:
		return nil, 0, 0, fmt.Errorf("%w: unknown scheme", ErrVolumeChain)
	}
	m := &multiReaderAt{}
	for _, p := range parts {
		p.start = m.size
		m.parts = append(m.parts, p)
		m.size += p.size
		if m.size > maxTotal {
			return nil, 0, 0, fmt.Errorf("%w: joined size exceeds %d bytes", ErrVolumeChain, maxTotal)
		}
	}
	return m, m.size, len(parts), nil
}

// eggVolumeHeader parses an EGG volume's header and archive extras,
// returning its header id, split links, and the offset of the first byte
// after the archive header's EOFARC.
func eggVolumeHeader(r io.ReaderAt, size int64) (id, prev, next uint32, body int64, err error) {
	e := &eggReader{r: r, size: size}
	head, err := e.read(14)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if binary.LittleEndian.Uint32(head) != eggHeaderMagic {
		return 0, 0, 0, 0, errors.New("bad EGG magic")
	}
	id = binary.LittleEndian.Uint32(head[6:])
	split := false
	for range maxArchiveHeaders {
		magic, err := e.u32()
		if err != nil {
			return 0, 0, 0, 0, err
		}
		if magic == eggEOFARC {
			if !split {
				return 0, 0, 0, 0, errors.New("EGG volume has no split header")
			}
			return id, prev, next, e.pos, nil
		}
		_, sz, err := e.extra()
		if err != nil {
			return 0, 0, 0, 0, err
		}
		if magic == eggSplitMagic && sz >= 8 {
			b, err := e.read(8)
			if err != nil {
				return 0, 0, 0, 0, err
			}
			prev, next, split = binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), true
			sz -= 8
		}
		if err := e.skip(sz); err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return 0, 0, 0, 0, errors.New("EGG volume header has too many extras")
}

type readerPart struct {
	r         io.ReaderAt
	off, size int64 // window [off, off+size) of r
	start     int64 // logical offset of the window
}

// multiReaderAt concatenates reader windows into one io.ReaderAt.
type multiReaderAt struct {
	parts []readerPart
	size  int64
}

// Size is the logical length of the joined volumes.
func (m *multiReaderAt) Size() int64 { return m.size }

func (m *multiReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	n := 0
	for i := range m.parts {
		if len(p) == 0 {
			break
		}
		part := &m.parts[i]
		if off >= part.start+part.size {
			continue
		}
		rel := off - part.start
		want := min(int64(len(p)), part.size-rel)
		got, err := part.r.ReadAt(p[:want], part.off+rel)
		n += got
		off += int64(got)
		p = p[got:]
		if int64(got) < want {
			if err == nil || errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
	}
	if len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}
