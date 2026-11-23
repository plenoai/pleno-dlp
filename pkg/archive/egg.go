package archive

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// ALZip EGG member extraction. Layout (ESTsoft EGG format documentation, as
// implemented by ClamAV libclamav/egg.c), little-endian throughout:
//
//	EGG header (14)  magic 0x41474745, version u16, header id u32, reserved u32
//	  extra fields   split / solid / archive encrypt headers, then EOFARC
//	per file:
//	  file header    magic 0x0A8590E3, file id u32, file length u64
//	  extra fields   filename, comment, windows/posix info, encrypt, then EOFARC
//	  block(s)       magic 0x02B50C13, method u8, hint u8, usize u32, csize u32,
//	                 crc32 u32, EOFARC, csize bytes of data
//	archive comment  (optional extra field), EOFARC
//
// An extra field is magic u32, flag u8, then a u16 size (u32 when flag&1)
// and the body. Store, raw deflate, bzip2, and LZMA blocks are expanded
// through the shared member budget path. Solid archives (one block stream
// for the whole archive, cut into members by their file lengths) and the
// first volume of a split archive (members complete in this volume, plus the
// decodable prefix of the member cut at the volume end) are extracted too.
//
// Remaining coverage gaps, scanned raw instead:
//   - AZO blocks (method 3): ESTsoft's codec has no public specification and
//     its reference source forbids use in other EGG implementations, so it is
//     not ported; the member is an "unsupported-compression" gap.
//   - split volumes that are missing: filesystem and S3 sources join sibling
//     volumes through JoinVolumes (volumes.go), so a set only reaches the
//     walker volume by volume when a volume is absent or the chain breaks;
//     a volume that then starts or ends mid-stream is a "split-volume" gap.
//   - encrypted members ("encrypted").

const (
	eggEOFARC        = 0x08E28222
	eggHeaderMagic   = 0x41474745
	eggFileMagic     = 0x0A8590E3
	eggBlockMagic    = 0x02B50C13
	eggEncryptMagic  = 0x08D1470F
	eggWindowsMagic  = 0x2C86950B
	eggPosixMagic    = 0x1EE922E5
	eggFilenameMagic = 0x0A8591AC
	eggCommentMagic  = 0x04C63672
	eggSplitMagic    = 0x24F5A262
	eggSolidMagic    = 0x24E5A060
	eggDummyMagic    = 0x07463307
	eggSkipMagic     = 0xFFFF0000

	eggFlagSize4       = 0x01
	eggNameEncrypted   = 0x04
	eggNameCodepage    = 0x08
	eggNameRelative    = 0x10
	eggWinDirectory    = 0x40
	eggPosixTypeMask   = 0o170000
	eggPosixRegular    = 0o100000
	eggMaxNameBytes    = 4096
	eggMethodStore     = 0
	eggMethodDeflate   = 1
	eggMethodBzip2     = 2
	eggMethodAZO       = 3
	eggMethodLZMA      = 4
	eggMaxBlocksPerMem = 10_000
	eggMaxLZMADict     = 64 << 20 // mirrors the zstd window cap
)

type eggBlock struct {
	method       byte
	offset       int64
	csize, usize int64
}

type eggMember struct {
	name       string
	length     int64 // uncompressed file length from the file header
	encrypted  bool
	nonRegular bool
	truncated  bool // last block cut at the end of a split volume
	blocks     []eggBlock
}

// eggArchive is a parsed EGG volume. In a solid archive the blocks belong to
// the archive (solidBlocks) and members only carry their lengths.
type eggArchive struct {
	members     []eggMember
	solid       bool
	splitPrev   uint32
	splitNext   uint32
	solidBlocks []eggBlock
	truncated   bool // the volume ends inside a block (split first volume)
}

type eggReader struct {
	r    io.ReaderAt
	size int64
	pos  int64
}

func (e *eggReader) read(n int) ([]byte, error) {
	if n < 0 || e.pos+int64(n) > e.size {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	if _, err := e.r.ReadAt(b, e.pos); err != nil {
		return nil, err
	}
	e.pos += int64(n)
	return b, nil
}

func (e *eggReader) u32() (uint32, error) {
	b, err := e.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// extra reads the flag and size of an extra field whose magic was consumed.
func (e *eggReader) extra() (flag byte, size int64, err error) {
	b, err := e.read(1)
	if err != nil {
		return 0, 0, err
	}
	flag = b[0]
	if flag&eggFlagSize4 != 0 {
		v, err := e.u32()
		return flag, int64(v), err
	}
	s, err := e.read(2)
	if err != nil {
		return 0, 0, err
	}
	return flag, int64(binary.LittleEndian.Uint16(s)), nil
}

func (e *eggReader) skip(n int64) error {
	if n < 0 || e.pos+n > e.size {
		return io.ErrUnexpectedEOF
	}
	e.pos += n
	return nil
}

// encryptBody returns the body length of an encrypt header, whose size field
// (unlike every other extra field) counts its own 7-byte header.
func encryptBody(size int64) int64 {
	if size >= 7 {
		return size - 7
	}
	return size
}

var (
	errEggUnsupportedLayout = errors.New("unsupported EGG layout")
	errEggSplitContinuation = errors.New("EGG split continuation volume starts mid-stream")
)

// parseEgg returns the volume's members. A split continuation volume returns
// errEggSplitContinuation because its bytes continue the previous volume.
func parseEgg(r io.ReaderAt, size int64, maxHeaders int) (*eggArchive, int, error) {
	e := &eggReader{r: r, size: size}
	arc := &eggArchive{}
	head, err := e.read(14)
	if err != nil {
		return arc, 0, err
	}
	if binary.LittleEndian.Uint32(head) != eggHeaderMagic {
		return arc, 0, errors.New("bad EGG magic")
	}
	headers := 0
	var archiveEncrypted bool
	for {
		magic, err := e.u32()
		if err != nil {
			return arc, headers, err
		}
		if magic == eggEOFARC {
			break
		}
		_, sz, err := e.extra()
		if err != nil {
			return arc, headers, err
		}
		switch magic {
		case eggSolidMagic:
			arc.solid = true
		case eggSplitMagic:
			body, err := e.read(int(min(sz, 8)))
			if err != nil {
				return arc, headers, err
			}
			if len(body) == 8 {
				arc.splitPrev = binary.LittleEndian.Uint32(body)
				arc.splitNext = binary.LittleEndian.Uint32(body[4:])
			}
			sz -= int64(len(body))
		case eggEncryptMagic:
			archiveEncrypted = true
			sz = encryptBody(sz)
		}
		if err := e.skip(sz); err != nil {
			return arc, headers, err
		}
	}
	if arc.splitPrev != 0 {
		return arc, headers, errEggSplitContinuation
	}
	split := arc.splitNext != 0
	for e.pos < e.size {
		magic, err := e.u32()
		if err != nil {
			return arc, headers, err
		}
		switch magic {
		case eggEOFARC:
			return arc, headers, nil
		case eggCommentMagic, eggDummyMagic, eggSkipMagic:
			_, sz, err := e.extra()
			if err == nil {
				err = e.skip(sz)
			}
			if err != nil {
				return arc, headers, err
			}
		case eggFileMagic:
			headers++
			if headers > maxHeaders {
				return arc, headers, errEggHeaderLimit
			}
			idLen, err := e.read(12) // file id, file length
			if err != nil {
				return arc, headers, err
			}
			m := eggMember{encrypted: archiveEncrypted, length: int64(binary.LittleEndian.Uint64(idLen[4:]))}
			if m.length < 0 {
				return arc, headers, errors.New("EGG file length overflows")
			}
			if err := parseEggFileExtras(e, &m); err != nil {
				return arc, headers, err
			}
			arc.members = append(arc.members, m)
		case eggBlockMagic:
			if len(arc.members) == 0 {
				return arc, headers, errors.New("EGG block before file header")
			}
			b, err := e.read(14)
			if err != nil {
				return arc, headers, err
			}
			end, err := e.u32()
			if err != nil {
				return arc, headers, err
			}
			if end != eggEOFARC {
				return arc, headers, errors.New("EGG block header missing end marker")
			}
			blk := eggBlock{
				method: b[0],
				usize:  int64(binary.LittleEndian.Uint32(b[2:6])),
				csize:  int64(binary.LittleEndian.Uint32(b[6:10])),
				offset: e.pos,
			}
			cut := false
			if err := e.skip(blk.csize); err != nil {
				if !split {
					return arc, headers, err
				}
				// Compressed data may be cut at a volume boundary; keep the
				// prefix this volume holds.
				blk.csize, cut = e.size-e.pos, true
				e.pos = e.size
			}
			blocks := &arc.members[len(arc.members)-1].blocks
			if arc.solid {
				blocks = &arc.solidBlocks
			}
			if len(*blocks) >= eggMaxBlocksPerMem {
				return arc, headers, errors.New("EGG member has too many blocks")
			}
			*blocks = append(*blocks, blk)
			if cut {
				arc.truncated = true
				arc.members[len(arc.members)-1].truncated = true
				return arc, headers, nil
			}
		default:
			return arc, headers, fmt.Errorf("unknown EGG header 0x%08x", magic)
		}
	}
	if split {
		arc.truncated = true
		if len(arc.members) > 0 {
			arc.members[len(arc.members)-1].truncated = true
		}
	}
	return arc, headers, nil
}

var errEggHeaderLimit = fmt.Errorf("EGG entry count exceeds %d", maxArchiveHeaders)

func parseEggFileExtras(e *eggReader, m *eggMember) error {
	for {
		magic, err := e.u32()
		if err != nil {
			return err
		}
		if magic == eggEOFARC {
			return nil
		}
		flag, sz, err := e.extra()
		if err != nil {
			return err
		}
		switch magic {
		case eggFilenameMagic:
			body, err := e.read(int(min(sz, eggMaxNameBytes+6)))
			if err != nil {
				return err
			}
			if err := e.skip(sz - int64(len(body))); err != nil {
				return err
			}
			if flag&eggNameEncrypted != 0 {
				m.encrypted = true
			}
			if flag&eggNameCodepage != 0 && len(body) >= 2 {
				body = body[2:]
			}
			if flag&eggNameRelative != 0 && len(body) >= 4 {
				body = body[4:]
			}
			m.name = string(body)
		case eggWindowsMagic:
			body, err := e.read(int(min(sz, 64)))
			if err != nil {
				return err
			}
			if len(body) >= 9 && body[8]&eggWinDirectory != 0 {
				m.nonRegular = true
			}
			if err := e.skip(sz - int64(len(body))); err != nil {
				return err
			}
		case eggPosixMagic:
			body, err := e.read(int(min(sz, 64)))
			if err != nil {
				return err
			}
			if len(body) >= 4 {
				if mode := binary.LittleEndian.Uint32(body); mode&eggPosixTypeMask != 0 && mode&eggPosixTypeMask != eggPosixRegular {
					m.nonRegular = true
				}
			}
			if err := e.skip(sz - int64(len(body))); err != nil {
				return err
			}
		case eggEncryptMagic:
			m.encrypted = true
			if err := e.skip(encryptBody(sz)); err != nil {
				return err
			}
		default:
			if err := e.skip(sz); err != nil {
				return err
			}
		}
	}
}

func (s *walkState) walkEgg(name string, data *spool, depth int) error {
	arc, headers, err := parseEgg(data.readerAt(), data.size, maxArchiveHeaders-s.headers)
	s.headers += headers
	if errors.Is(err, errEggHeaderLimit) {
		s.stop("max-headers", name, err)
		return nil
	}
	members := arc.members
	if err != nil {
		kind := "corrupt-archive"
		switch {
		case errors.Is(err, errEggSplitContinuation):
			kind = "split-volume"
		case errors.Is(err, errEggUnsupportedLayout):
			kind = "unsupported-compression"
		}
		// Keep the pre-extraction behaviour (raw scan) so nothing is lost.
		s.partial(kind, name, err)
		if len(members) == 0 {
			return s.emitEntry(name, data)
		}
	}
	if arc.truncated {
		s.partial("split-volume", name, fmt.Errorf("EGG split volume %d continues in another file; only this volume is scanned", arc.splitNext))
	}
	if arc.solid {
		return s.walkEggSolid(name, data, arc, depth)
	}
	for i, m := range members {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		label, clean, ok := s.eggMemberLabel(i, m)
		if !ok || len(m.blocks) == 0 {
			continue
		}
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", label, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		input, declared, err := s.eggBlocksReader(data, m.blocks, m.truncated)
		if err != nil {
			s.partial("unsupported-compression", label, err)
			continue
		}
		if m.truncated {
			declared = -1
		}
		if err := s.walkMember(name+"!"+clean, label, input, declared, depth); err != nil {
			return err
		}
	}
	return nil
}

// eggMemberLabel reports the member's label and safe path, recording a gap
// and returning ok=false for members that are not scanned.
func (s *walkState) eggMemberLabel(i int, m eggMember) (label, clean string, ok bool) {
	label = m.name
	if label == "" {
		label = fmt.Sprintf("member-%d", i)
	}
	hasData := len(m.blocks) > 0 || m.length > 0
	if m.nonRegular {
		if hasData {
			s.partial("special-file", label, errors.New("non-regular entries are not scanned"))
		}
		return label, "", false
	}
	if m.encrypted && hasData {
		s.partial("encrypted", label, errors.New("encrypted EGG member"))
		return label, "", false
	}
	clean, ok = safeEntryName(label)
	if !ok {
		s.partial("path", label, errors.New("unsafe archive path rejected"))
	}
	return label, clean, ok
}

// walkEggSolid decodes the archive-wide block stream once and cuts it into
// members by their declared file lengths, in header order. Bytes of members
// that are not scanned are discarded under the expansion budget.
func (s *walkState) walkEggSolid(name string, data *spool, arc *eggArchive, depth int) error {
	if len(arc.solidBlocks) == 0 {
		return nil
	}
	stream, _, err := s.eggBlocksReader(data, arc.solidBlocks, arc.truncated)
	if err != nil {
		s.partial("unsupported-compression", name, err)
		return s.emitEntry(name, data)
	}
	for i, m := range arc.members {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		section := &io.LimitedReader{R: stream, N: m.length}
		label, clean, ok := s.eggMemberLabel(i, m)
		if ok && m.length > 0 {
			if s.files >= s.limits.MaxFiles {
				s.stop("max-files", label, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
				return nil
			}
			declared := m.length
			if arc.truncated && i == len(arc.members)-1 {
				declared = -1
			}
			if err := s.walkMember(name+"!"+clean, label, section, declared, depth); err != nil {
				return err
			}
		}
		// Realign the shared stream on the next member even when this one
		// was skipped or rejected before it was read to the end.
		if section.N > 0 {
			remaining := s.limits.MaxExpandedBytes - s.expanded
			if section.N > remaining {
				s.rejectBudget("max-expanded-bytes", name, fmt.Errorf("solid EGG stream exceeds %d", s.limits.MaxExpandedBytes))
				return nil
			}
			n, err := io.Copy(io.Discard, section)
			s.expanded += n
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				s.partial("corrupt-entry", label, err)
				return nil
			}
			if section.N > 0 { // stream ended early
				if !arc.truncated {
					s.partial("corrupt-entry", label, errors.New("solid EGG stream shorter than declared file lengths"))
				}
				return nil
			}
		}
	}
	return nil
}

// eggBlocksReader chains the decoders of consecutive blocks. When the last
// block was cut at a split-volume boundary, its decoder's unexpected EOF ends
// the stream cleanly so the decoded prefix is still scanned.
func (s *walkState) eggBlocksReader(data *spool, blocks []eggBlock, truncated bool) (io.Reader, int64, error) {
	readers := make([]io.Reader, 0, len(blocks))
	var declared int64
	for i, b := range blocks {
		raw := io.NewSectionReader(data.readerAt(), b.offset, b.csize)
		var r io.Reader
		switch b.method {
		case eggMethodStore:
			r = raw
		case eggMethodDeflate:
			r = flate.NewReader(bufio.NewReader(raw))
		case eggMethodBzip2:
			r = bzip2.NewReader(bufio.NewReader(raw))
		case eggMethodLZMA:
			lr, err := eggLZMAReader(raw, b.usize)
			if err != nil {
				return nil, 0, err
			}
			r = lr
		case eggMethodAZO:
			return nil, 0, errors.New("AZO-compressed EGG member (proprietary codec, not supported)")
		default:
			return nil, 0, fmt.Errorf("unknown EGG compression method %d", b.method)
		}
		if truncated && i == len(blocks)-1 {
			r = &cutReader{r: r}
		}
		readers = append(readers, r)
		declared += b.usize
	}
	return contextReader{ctx: s.ctx, r: io.MultiReader(readers...)}, declared, nil
}

// eggLZMAReader decodes an EGG LZMA block: a 4-byte header (LZMA SDK version
// u16, properties size u16, as in ZIP method 14) and the 5-byte properties,
// followed by a raw LZMA stream. The classic .lzma header is synthesized
// from the properties and the block's uncompressed size.
func eggLZMAReader(raw io.Reader, usize int64) (io.Reader, error) {
	var head [9]byte
	if _, err := io.ReadFull(raw, head[:]); err != nil {
		return nil, fmt.Errorf("EGG LZMA header: %w", err)
	}
	if binary.LittleEndian.Uint16(head[2:]) != 5 {
		return nil, fmt.Errorf("EGG LZMA properties size %d", binary.LittleEndian.Uint16(head[2:]))
	}
	hdr := make([]byte, 0, 13)
	hdr = append(hdr, head[4:9]...)
	hdr = binary.LittleEndian.AppendUint64(hdr, uint64(usize))
	dict := binary.LittleEndian.Uint32(head[5:9])
	if dict > eggMaxLZMADict {
		return nil, fmt.Errorf("EGG LZMA dictionary %d exceeds %d", dict, eggMaxLZMADict)
	}
	cfg := lzma.ReaderConfig{DictCap: max(int(dict), lzma.MinDictCap)}
	return cfg.NewReader(io.MultiReader(bytes.NewReader(hdr), bufio.NewReader(raw)))
}

// cutReader ends a stream cut at a volume boundary without an error. Some
// decoders (lzma) still hold decoded bytes when they report the unexpected
// EOF, so reading continues until a read makes no progress.
type cutReader struct {
	r   io.Reader
	cut bool
}

func (c *cutReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == nil || err == io.EOF {
		return n, err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, err
	}
	if n == 0 && c.cut {
		return 0, io.EOF
	}
	c.cut = true
	return n, nil
}
