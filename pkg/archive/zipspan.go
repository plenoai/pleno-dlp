package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Spanned PKZIP sets ("<base>.z01", "<base>.z02", ..., "<base>.zip") store
// every local-header offset relative to the start of the disk (volume) that
// holds it, and the end-of-central-directory record in the last volume names
// the disk count and the disk where the central directory starts. Plain
// concatenation therefore points every entry at the wrong byte. joinZipSpan
// concatenates the volumes verbatim and appends a rewritten central
// directory whose offsets are absolute in the joined stream, plus a fresh
// end record, so the ordinary zip walker reads the result. The end record's
// disk number must equal the volume count minus one, which rejects a set
// with a missing, extra, or unrelated volume.

const (
	zipEOCDSig        = 0x06054b50
	zipSpanMarker     = 0x08074b50 // "PK\x07\x08" ahead of the first local header of a spanned set
	zip64EOCDSig      = 0x06064b50
	zip64LocatorSig   = 0x07064b50
	zipCentralSig     = 0x02014b50
	zipEOCDLen        = 22
	zip64LocatorLen   = 20
	zip64EOCDLen      = 56
	maxZipCommentLen  = 0xffff
	maxSpanCentralDir = 64 << 20
)

type zipEnd struct {
	disk, cdDisk     uint32
	entries          uint64
	cdSize, cdOffset uint64
}

// readZipEnd locates the end record (and its ZIP64 form) in the last volume.
func readZipEnd(r io.ReaderAt, size int64) (zipEnd, error) {
	n := min(size, zipEOCDLen+maxZipCommentLen)
	tail := make([]byte, n)
	if _, err := r.ReadAt(tail, size-n); err != nil && !errors.Is(err, io.EOF) {
		return zipEnd{}, err
	}
	at := -1
	for i := len(tail) - zipEOCDLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == zipEOCDSig && i+zipEOCDLen+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			at = i
			break
		}
	}
	if at < 0 {
		return zipEnd{}, errors.New("last volume has no zip end record")
	}
	b := tail[at:]
	e := zipEnd{
		disk:     uint32(binary.LittleEndian.Uint16(b[4:])),
		cdDisk:   uint32(binary.LittleEndian.Uint16(b[6:])),
		entries:  uint64(binary.LittleEndian.Uint16(b[10:])),
		cdSize:   uint64(binary.LittleEndian.Uint32(b[12:])),
		cdOffset: uint64(binary.LittleEndian.Uint32(b[16:])),
	}
	if e.disk != 0xffff && e.cdDisk != 0xffff && e.entries != 0xffff && e.cdSize != 0xffffffff && e.cdOffset != 0xffffffff {
		return e, nil
	}
	// ZIP64: the locator sits immediately before the end record and points
	// at the ZIP64 end record, which for a spanned set lives in this volume.
	locAt := size - n + int64(at) - zip64LocatorLen
	if locAt < 0 {
		return zipEnd{}, errors.New("zip64 locator missing")
	}
	loc := make([]byte, zip64LocatorLen)
	if _, err := r.ReadAt(loc, locAt); err != nil {
		return zipEnd{}, err
	}
	if binary.LittleEndian.Uint32(loc) != zip64LocatorSig {
		return zipEnd{}, errors.New("zip64 locator missing")
	}
	// The locator's offset is relative to its disk; for a spanned set the
	// ZIP64 end record is written right before the locator.
	recAt := locAt - zip64EOCDLen
	if recAt < 0 {
		return zipEnd{}, errors.New("zip64 end record missing")
	}
	rec := make([]byte, zip64EOCDLen)
	if _, err := r.ReadAt(rec, recAt); err != nil {
		return zipEnd{}, err
	}
	if binary.LittleEndian.Uint32(rec) != zip64EOCDSig {
		return zipEnd{}, errors.New("zip64 end record missing")
	}
	return zipEnd{
		disk:     binary.LittleEndian.Uint32(rec[16:]),
		cdDisk:   binary.LittleEndian.Uint32(rec[20:]),
		entries:  binary.LittleEndian.Uint64(rec[32:]),
		cdSize:   binary.LittleEndian.Uint64(rec[40:]),
		cdOffset: binary.LittleEndian.Uint64(rec[48:]),
	}, nil
}

// joinZipSpan returns the joined parts (verbatim volumes followed by a
// rewritten central directory) of a spanned zip set.
func joinZipSpan(vols []Volume, maxTotal int64) ([]readerPart, error) {
	if len(vols) < 2 {
		return nil, errors.New("spanned zip needs at least two volumes")
	}
	last := vols[len(vols)-1]
	end, err := readZipEnd(last.R, last.Size)
	if err != nil {
		return nil, err
	}
	if int(end.disk) != len(vols)-1 {
		return nil, fmt.Errorf("zip end record names disk %d of a %d-volume set", end.disk, len(vols))
	}
	if int(end.cdDisk) >= len(vols) {
		return nil, errors.New("central directory disk out of range")
	}
	starts := make([]int64, len(vols)+1)
	parts := make([]readerPart, 0, len(vols)+1)
	for i, v := range vols {
		parts = append(parts, readerPart{r: v.R, size: v.Size, start: starts[i]})
		starts[i+1] = starts[i] + v.Size
	}
	total := starts[len(vols)]
	if end.cdSize > maxSpanCentralDir || end.cdSize > uint64(total) {
		return nil, errors.New("central directory size out of range")
	}
	cdStart := starts[end.cdDisk] + int64(end.cdOffset)
	if end.cdOffset > uint64(total) || cdStart+int64(end.cdSize) > total {
		return nil, errors.New("central directory exceeds the joined volumes")
	}
	joined := &multiReaderAt{parts: parts, size: total}
	cd := make([]byte, end.cdSize)
	if _, err := joined.ReadAt(cd, cdStart); err != nil {
		return nil, err
	}
	out, entries, err := rewriteSpanCentralDir(cd, starts[:len(vols)], total)
	if err != nil {
		return nil, err
	}
	if entries != end.entries {
		return nil, fmt.Errorf("central directory holds %d entries, end record says %d", entries, end.entries)
	}
	out = appendZipEnd(out, entries, uint64(len(out)), uint64(total))
	if total+int64(len(out)) > maxTotal {
		return nil, fmt.Errorf("joined size exceeds %d bytes", maxTotal)
	}
	return append(parts, readerPart{r: bytes.NewReader(out), size: int64(len(out)), start: total}), nil
}

// rewriteSpanCentralDir copies the central directory, turning each entry's
// (disk, disk-relative offset) into an absolute offset on disk 0.
func rewriteSpanCentralDir(cd []byte, starts []int64, total int64) ([]byte, uint64, error) {
	out := make([]byte, 0, len(cd))
	var entries uint64
	for p := 0; p < len(cd); {
		if len(cd)-p < 46 || binary.LittleEndian.Uint32(cd[p:]) != zipCentralSig {
			return nil, 0, errors.New("invalid central directory header")
		}
		h := cd[p:]
		nameLen := int(binary.LittleEndian.Uint16(h[28:]))
		extraLen := int(binary.LittleEndian.Uint16(h[30:]))
		commentLen := int(binary.LittleEndian.Uint16(h[32:]))
		step := 46 + nameLen + extraLen + commentLen
		if step > len(cd)-p {
			return nil, 0, errors.New("central directory header exceeds its size")
		}
		rec := append([]byte(nil), h[:step]...)
		usize := binary.LittleEndian.Uint32(rec[24:])
		csize := binary.LittleEndian.Uint32(rec[20:])
		disk := uint64(binary.LittleEndian.Uint16(rec[34:]))
		off := uint64(binary.LittleEndian.Uint32(rec[42:]))
		offField := -1 // index of the ZIP64 offset value inside rec
		extra := rec[46+nameLen : 46+nameLen+extraLen]
		for e := 0; e+4 <= len(extra); {
			id := binary.LittleEndian.Uint16(extra[e:])
			sz := int(binary.LittleEndian.Uint16(extra[e+2:]))
			if e+4+sz > len(extra) {
				break
			}
			if id == 0x0001 {
				f := e + 4
				next := func(n int) int {
					if f+n > e+4+sz {
						return -1
					}
					at := f
					f += n
					return at
				}
				if usize == 0xffffffff {
					next(8)
				}
				if csize == 0xffffffff {
					next(8)
				}
				if off == 0xffffffff {
					if at := next(8); at >= 0 {
						offField = 46 + nameLen + at
						off = binary.LittleEndian.Uint64(extra[at:])
					}
				}
				if disk == 0xffff {
					if at := next(4); at >= 0 {
						disk = uint64(binary.LittleEndian.Uint32(extra[at:]))
						binary.LittleEndian.PutUint32(extra[at:], 0)
					}
				}
			}
			e += 4 + sz
		}
		if disk >= uint64(len(starts)) {
			return nil, 0, fmt.Errorf("entry names disk %d of a %d-volume set", disk, len(starts))
		}
		abs := uint64(starts[disk]) + off
		if off > uint64(total) || abs >= uint64(total) {
			return nil, 0, errors.New("entry offset exceeds the joined volumes")
		}
		binary.LittleEndian.PutUint16(rec[34:], 0)
		switch {
		case offField >= 0:
			binary.LittleEndian.PutUint64(rec[offField:], abs)
		case abs < 0xffffffff:
			binary.LittleEndian.PutUint32(rec[42:], uint32(abs))
		default:
			return nil, 0, errors.New("entry offset needs zip64")
		}
		out = append(out, rec...)
		entries++
		p += step
	}
	return out, entries, nil
}

// appendZipEnd appends a single-disk end record (ZIP64 when required) for
// a central directory of cdSize bytes starting at cdOffset.
func appendZipEnd(b []byte, entries, cdSize, cdOffset uint64) []byte {
	le := binary.LittleEndian
	if entries >= 0xffff || cdSize >= 0xffffffff || cdOffset >= 0xffffffff {
		recAt := cdOffset + cdSize
		b = le.AppendUint32(b, zip64EOCDSig)
		b = le.AppendUint64(b, zip64EOCDLen-12)
		b = le.AppendUint16(b, 45)
		b = le.AppendUint16(b, 45)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, entries)
		b = le.AppendUint64(b, entries)
		b = le.AppendUint64(b, cdSize)
		b = le.AppendUint64(b, cdOffset)
		b = le.AppendUint32(b, zip64LocatorSig)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, recAt)
		b = le.AppendUint32(b, 1)
		entries, cdSize, cdOffset = 0xffff, 0xffffffff, 0xffffffff
	}
	b = le.AppendUint32(b, zipEOCDSig)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, uint16(entries))
	b = le.AppendUint16(b, uint16(entries))
	b = le.AppendUint32(b, uint32(cdSize))
	b = le.AppendUint32(b, uint32(cdOffset))
	b = le.AppendUint16(b, 0)
	return b
}

// zipOpenError classifies a zip that failed to open. One volume of a
// spanned/split set walked without its siblings is a split-volume gap, not
// corruption: a terminal ".zip" whose end record names disk > 0, or a head
// ".z01" that starts with the spanning marker and has no end record.
func zipOpenError(name string, data *spool, err error) error {
	if end, endErr := readZipEnd(data.readerAt(), data.size); endErr == nil {
		if end.disk != 0 || end.cdDisk != 0 {
			return &PartialError{Kind: "split-volume", Entry: name, Err: fmt.Errorf("zip volume %d of a spanned set was scanned without its sibling volumes: %w", end.disk+1, err)}
		}
	} else if head := make([]byte, 4); data.size >= 4 {
		if _, rerr := data.readerAt().ReadAt(head, 0); rerr == nil && binary.LittleEndian.Uint32(head) == zipSpanMarker {
			return &PartialError{Kind: "split-volume", Entry: name, Err: fmt.Errorf("first volume of a spanned zip set was scanned without its sibling volumes: %w", err)}
		}
	}
	return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
}

// OrphanVolumeName reports whether name is a volume that, scanned on its
// own, cannot be expanded from its first bytes: any spanned-zip volume
// (".z02".., or the ".zip" terminal, whose head is mid-member data) or a
// byte-split continuation (".002"..). Sources that drop binary non-archives
// still emit such files so the engine can report the gap and scan the raw
// bytes; a linked set never reaches this path because it is joined first.
func OrphanVolumeName(name string) bool {
	id, ok := ParseVolumeName(name)
	if !ok {
		return false
	}
	switch id.Scheme {
	case VolumeZipSpan:
		return id.Index != 1
	case VolumeBytes:
		return id.Index >= 2
	}
	return false
}

// OrphanVolumeGap returns a split-volume PartialError for a body named by
// OrphanVolumeName that arrived without its sibling volumes (#958):
//
//   - a ".zip" whose end record names disk > 0 (the terminal of a spanned
//     set); a complete single-disk ".zip" is not a gap;
//   - a ".z02".. or ".002".. continuation whose content is binary, since a
//     text file that merely carries such a suffix is scanned as text.
//
// Callers route bodies that LooksLikeArchive to the walker instead and
// always scan the raw bytes of an orphan. It returns nil otherwise.
func OrphanVolumeGap(name string, r io.ReaderAt, size int64) error {
	id, ok := ParseVolumeName(name)
	if !ok || size <= 0 {
		return nil
	}
	switch {
	case id.Scheme == VolumeZipSpan && id.Index == 0:
		if size < zipEOCDLen {
			return nil
		}
		end, err := readZipEnd(r, size)
		if err != nil || (end.disk == 0 && end.cdDisk == 0) {
			return nil
		}
		return &PartialError{Kind: "split-volume", Entry: name, Err: fmt.Errorf("zip volume %d (last) of a spanned set was scanned without its sibling volumes", end.disk+1)}
	case (id.Scheme == VolumeZipSpan && id.Index >= 2) || (id.Scheme == VolumeBytes && id.Index >= 2):
		head := make([]byte, min(size, 512))
		n, err := r.ReadAt(head, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil
		}
		if !looksBinary(head[:n]) {
			return nil
		}
		return &PartialError{Kind: "split-volume", Entry: name, Err: fmt.Errorf("volume %d of a multi-volume archive was scanned without its sibling volumes", id.Index)}
	}
	return nil
}

// looksBinary reports a NUL byte or invalid UTF-8 (ignoring a rune cut at
// the end of the sample).
func looksBinary(p []byte) bool {
	if bytes.IndexByte(p, 0) >= 0 {
		return true
	}
	for cut := 0; cut < 4 && cut <= len(p); cut++ {
		if utf8.Valid(p[:len(p)-cut]) {
			return false
		}
	}
	return true
}
