package archive

import (
	"bufio"
	"compress/bzip2"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
// and the body. Store, raw deflate, and bzip2 blocks are expanded through
// the shared member budget path; AZO, LZMA, encrypted, solid, and split
// archives are coverage gaps and the raw bytes are scanned instead.

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
)

type eggBlock struct {
	method       byte
	offset       int64
	csize, usize int64
}

type eggMember struct {
	name       string
	encrypted  bool
	nonRegular bool
	blocks     []eggBlock
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

var errEggUnsupportedLayout = errors.New("unsupported EGG layout")

// parseEgg returns the archive's members. Solid and split archives return
// errEggUnsupportedLayout because their blocks are not per-member streams.
func parseEgg(r io.ReaderAt, size int64, maxHeaders int) ([]eggMember, int, error) {
	e := &eggReader{r: r, size: size}
	head, err := e.read(14)
	if err != nil {
		return nil, 0, err
	}
	if binary.LittleEndian.Uint32(head) != eggHeaderMagic {
		return nil, 0, errors.New("bad EGG magic")
	}
	headers := 0
	var archiveEncrypted bool
	for {
		magic, err := e.u32()
		if err != nil {
			return nil, headers, err
		}
		if magic == eggEOFARC {
			break
		}
		_, sz, err := e.extra()
		if err != nil {
			return nil, headers, err
		}
		switch magic {
		case eggSolidMagic:
			return nil, headers, fmt.Errorf("%w: solid compression", errEggUnsupportedLayout)
		case eggSplitMagic:
			return nil, headers, fmt.Errorf("%w: split volume", errEggUnsupportedLayout)
		case eggEncryptMagic:
			archiveEncrypted = true
			sz = encryptBody(sz)
		}
		if err := e.skip(sz); err != nil {
			return nil, headers, err
		}
	}
	var members []eggMember
	for e.pos < e.size {
		magic, err := e.u32()
		if err != nil {
			return members, headers, err
		}
		switch magic {
		case eggEOFARC:
			return members, headers, nil
		case eggCommentMagic:
			_, sz, err := e.extra()
			if err == nil {
				err = e.skip(sz)
			}
			if err != nil {
				return members, headers, err
			}
		case eggFileMagic:
			headers++
			if headers > maxHeaders {
				return members, headers, errEggHeaderLimit
			}
			if _, err := e.read(12); err != nil { // file id, file length
				return members, headers, err
			}
			m := eggMember{encrypted: archiveEncrypted}
			if err := parseEggFileExtras(e, &m); err != nil {
				return members, headers, err
			}
			members = append(members, m)
		case eggBlockMagic:
			if len(members) == 0 {
				return members, headers, errors.New("EGG block before file header")
			}
			b, err := e.read(14)
			if err != nil {
				return members, headers, err
			}
			end, err := e.u32()
			if err != nil {
				return members, headers, err
			}
			if end != eggEOFARC {
				return members, headers, errors.New("EGG block header missing end marker")
			}
			blk := eggBlock{
				method: b[0],
				usize:  int64(binary.LittleEndian.Uint32(b[2:6])),
				csize:  int64(binary.LittleEndian.Uint32(b[6:10])),
				offset: e.pos,
			}
			if err := e.skip(blk.csize); err != nil {
				return members, headers, err
			}
			m := &members[len(members)-1]
			if len(m.blocks) >= eggMaxBlocksPerMem {
				return members, headers, errors.New("EGG member has too many blocks")
			}
			m.blocks = append(m.blocks, blk)
		default:
			return members, headers, fmt.Errorf("unknown EGG header 0x%08x", magic)
		}
	}
	return members, headers, nil
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
	members, headers, err := parseEgg(data.readerAt(), data.size, maxArchiveHeaders-s.headers)
	s.headers += headers
	if errors.Is(err, errEggHeaderLimit) {
		s.stop("max-headers", name, err)
		return nil
	}
	if err != nil {
		kind := "corrupt-archive"
		if errors.Is(err, errEggUnsupportedLayout) {
			kind = "unsupported-compression"
		}
		// Keep the pre-extraction behaviour (raw scan) so nothing is lost.
		s.partial(kind, name, err)
		if len(members) == 0 {
			return s.emitEntry(name, data)
		}
	}
	for i, m := range members {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		label := m.name
		if label == "" {
			label = fmt.Sprintf("member-%d", i)
		}
		if m.nonRegular {
			if len(m.blocks) > 0 {
				s.partial("special-file", label, errors.New("non-regular entries are not scanned"))
			}
			continue
		}
		if len(m.blocks) == 0 {
			continue
		}
		if m.encrypted {
			s.partial("encrypted", label, errors.New("encrypted EGG member"))
			continue
		}
		clean, ok := safeEntryName(label)
		if !ok {
			s.partial("path", label, errors.New("unsafe archive path rejected"))
			continue
		}
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", label, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		input, declared, err := s.eggMemberReader(data, m)
		if err != nil {
			s.partial("unsupported-compression", label, err)
			continue
		}
		if err := s.walkMember(name+"!"+clean, label, input, declared, depth); err != nil {
			return err
		}
	}
	return nil
}

func (s *walkState) eggMemberReader(data *spool, m eggMember) (io.Reader, int64, error) {
	readers := make([]io.Reader, 0, len(m.blocks))
	var declared int64
	for _, b := range m.blocks {
		raw := io.NewSectionReader(data.readerAt(), b.offset, b.csize)
		switch b.method {
		case eggMethodStore:
			readers = append(readers, raw)
		case eggMethodDeflate:
			readers = append(readers, flate.NewReader(bufio.NewReader(raw)))
		case eggMethodBzip2:
			readers = append(readers, bzip2.NewReader(bufio.NewReader(raw)))
		case eggMethodAZO:
			return nil, 0, errors.New("AZO-compressed EGG member")
		case eggMethodLZMA:
			return nil, 0, errors.New("LZMA-compressed EGG member")
		default:
			return nil, 0, fmt.Errorf("unknown EGG compression method %d", b.method)
		}
		declared += b.usize
	}
	return contextReader{ctx: s.ctx, r: io.MultiReader(readers...)}, declared, nil
}
