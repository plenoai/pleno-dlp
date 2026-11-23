package archive

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/richardlehane/mscfb"
)

// Additional container formats: Electron ASAR, OLE2 compound files (with
// HWP 5.x section decompression and paragraph-text extraction). ALZip EGG
// members are extracted in egg.go.

var (
	oleMagic  = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	eggMagic  = []byte("EGGA")
	asarMagic = []byte{4, 0, 0, 0}
)

const (
	maxAsarHeaderBytes = 16 << 20
	maxAsarTreeDepth   = 64
)

func looksLikeAsar(prefix []byte) bool {
	return len(prefix) >= 25 && bytes.HasPrefix(prefix, asarMagic) && bytes.HasPrefix(prefix[16:], []byte(`{"files":`))
}

type asarNode struct {
	Files  map[string]*asarNode `json:"files"`
	Offset string               `json:"offset"`
	Size   int64                `json:"size"`
	Unpack bool                 `json:"unpacked"`
	Link   string               `json:"link"`
}

type asarMember struct {
	name         string
	offset, size int64
}

func (s *walkState) walkAsar(name string, data *spool, depth int) error {
	var head [16]byte
	if _, err := data.readerAt().ReadAt(head[:], 0); err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	pickleSize := int64(binary.LittleEndian.Uint32(head[4:8]))
	jsonLen := int64(binary.LittleEndian.Uint32(head[12:16]))
	if jsonLen > maxAsarHeaderBytes || 16+jsonLen > data.size || 8+pickleSize > data.size || jsonLen+8 > pickleSize {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: errors.New("invalid ASAR header size")}
	}
	header := make([]byte, jsonLen)
	if _, err := data.readerAt().ReadAt(header, 16); err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	var root asarNode
	if err := json.Unmarshal(header, &root); err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	base := 8 + pickleSize
	var members []asarMember
	type frame struct {
		prefix string
		node   *asarNode
		depth  int
	}
	stack := []frame{{node: &root}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.depth > maxAsarTreeDepth {
			s.partial("max-depth", name+"!"+f.prefix, errors.New("ASAR directory nesting too deep"))
			continue
		}
		keys := make([]string, 0, len(f.node.Files))
		for k := range f.node.Files {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		for _, k := range keys {
			child := f.node.Files[k]
			if child == nil {
				continue
			}
			p := k
			if f.prefix != "" {
				p = f.prefix + "/" + k
			}
			if child.Files != nil {
				stack = append(stack, frame{prefix: p, node: child, depth: f.depth + 1})
				continue
			}
			if s.headers >= maxArchiveHeaders {
				s.stop("max-headers", name, fmt.Errorf("ASAR entry count exceeds %d", maxArchiveHeaders))
				return nil
			}
			s.headers++
			switch {
			case child.Link != "":
				s.partial("symlink", p, errors.New("symlink entries are not scanned"))
				continue
			case child.Unpack:
				s.partial("asar-unpacked", p, errors.New("member is stored outside the archive (.asar.unpacked)"))
				continue
			}
			off, err := strconv.ParseInt(child.Offset, 10, 64)
			if err != nil || off < 0 || child.Size < 0 || base+off+child.Size > data.size || base+off+child.Size < base {
				s.partial("corrupt-entry", p, errors.New("ASAR member out of range"))
				continue
			}
			members = append(members, asarMember{name: p, offset: base + off, size: child.Size})
		}
	}
	for _, m := range members {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		clean, ok := safeEntryName(m.name)
		if !ok {
			s.partial("path", m.name, errors.New("unsafe archive path rejected"))
			continue
		}
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", m.name, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		if err := s.walkMember(name+"!"+clean, m.name, io.NewSectionReader(data.readerAt(), m.offset, m.size), m.size, depth); err != nil {
			return err
		}
	}
	return nil
}

// walkMember spools one member under the expansion budget and recurses.
func (s *walkState) walkMember(entryName, label string, input io.Reader, declared int64, depth int) error {
	value, accepted, err := s.expandedSpool(label, input, declared)
	if err != nil || !accepted {
		return err
	}
	walkErr := s.walk(entryName, value, depth+1)
	if cleanupErr := value.close(); cleanupErr != nil {
		s.partial("cleanup", entryName, cleanupErr)
	}
	return walkErr
}

const (
	hwpSignature      = "HWP Document File"
	hwpFlagCompressed = 1 << 0
	hwpFlagEncrypted  = 1 << 1
	hwpTagParaText    = 67
)

type oleStream struct {
	path string // display path; mscfb drops a non-printable first character
	raw  string // path with that character (\x01, \x05) restored
	file *mscfb.File
}

func (s *walkState) walkOLE(name string, data *spool, depth int) (err error) {
	defer func() {
		// mscfb is defensive but untrusted sector chains must never crash a scan.
		if r := recover(); r != nil {
			err = &PartialError{Kind: "corrupt-archive", Entry: name, Err: fmt.Errorf("OLE2 parser panic: %v", r)}
		}
	}()
	doc, err := mscfb.New(data.readerAt())
	if err != nil {
		return &PartialError{Kind: "corrupt-archive", Entry: name, Err: err}
	}
	var streams []oleStream
	var fileHeader *mscfb.File
	for {
		f, nextErr := doc.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			s.partial("corrupt-archive", name, nextErr)
			break
		}
		if f.FileInfo().IsDir() || f.Size <= 0 {
			continue
		}
		if s.headers >= maxArchiveHeaders {
			s.stop("max-headers", name, fmt.Errorf("OLE2 stream count exceeds %d", maxArchiveHeaders))
			return nil
		}
		s.headers++
		p := strings.Join(append(append([]string{}, f.Path...), f.Name), "/")
		if p == "FileHeader" {
			fileHeader = f
		}
		raw := p
		if f.Initial != 0 && f.Initial < 0x20 {
			raw = strings.Join(append(append([]string{}, f.Path...), string(rune(f.Initial))+f.Name), "/")
		}
		streams = append(streams, oleStream{path: p, raw: raw, file: f})
	}
	hwp, compressed := false, false
	if fileHeader != nil {
		head := make([]byte, 40)
		if n, _ := fileHeader.ReadAt(head, 0); n == len(head) && bytes.HasPrefix(head, []byte(hwpSignature)) {
			hwp = true
			flags := binary.LittleEndian.Uint32(head[36:40])
			compressed = flags&hwpFlagCompressed != 0
			if flags&hwpFlagEncrypted != 0 {
				s.partial("encrypted", name, errors.New("password-protected HWP document"))
				return nil
			}
		}
	}
	// The Word main stream goes first so the table stream it consumed is
	// known before the other streams are walked.
	consumed := map[string]bool{}
	if !hwp {
		for _, st := range streams {
			if st.path != "WordDocument" {
				continue
			}
			if s.files >= s.limits.MaxFiles {
				break
			}
			done, table, err := s.walkWordStream(name+"!"+sanitizeOLEPath(st.path), st, streams)
			if err != nil {
				return err
			}
			if done {
				consumed[st.path] = true
				if table != "" {
					consumed[table] = true
				}
			}
		}
	}
	for _, st := range streams {
		if s.terminal {
			return nil
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if consumed[st.path] {
			continue
		}
		base := st.raw[strings.LastIndexByte(st.raw, '/')+1:]
		if !hwp && oleMetadataStream(base) {
			continue
		}
		clean := sanitizeOLEPath(st.path)
		entryName := name + "!" + clean
		if s.files >= s.limits.MaxFiles {
			s.stop("max-files", st.path, fmt.Errorf("file count exceeds %d", s.limits.MaxFiles))
			return nil
		}
		var input io.Reader = io.NewSectionReader(st.file, 0, st.file.Size)
		declared := st.file.Size
		if hwp && compressed && hwpCompressedStream(st.raw) {
			input, declared = hwpInflater(input), -1
		}
		if hwp && strings.HasPrefix(st.path, "BodyText/Section") {
			if err := s.walkHWPSection(entryName, st.path, input, declared); err != nil {
				return err
			}
			continue
		}
		if !hwp {
			switch base {
			case oleNativeStream:
				done, err := s.walkOle10Native(entryName, st, depth)
				if err != nil {
					return err
				}
				if done {
					continue
				}
			case oleSummaryStream, oleDocSummary:
				done, err := s.walkPropertySet(entryName, st)
				if err != nil {
					return err
				}
				if done {
					continue
				}
			}
			if extract := officeStreamExtractor(st.path); extract != nil {
				done, err := s.walkOfficeStream(entryName, st, streams, extract)
				if err != nil {
					return err
				}
				if done {
					continue
				}
			}
		}
		if err := s.walkMember(entryName, st.path, input, declared, depth); err != nil {
			return err
		}
	}
	return nil
}

type officeExtractor func(stream []byte, tables map[string][]byte, out *textBuffer) error

// officeStreamExtractor selects the text extractor for the main stream of a
// legacy Word, Excel, or PowerPoint document.
func officeStreamExtractor(p string) officeExtractor {
	switch p {
	case "Workbook", "Book":
		return func(b []byte, _ map[string][]byte, out *textBuffer) error { return extractBIFFText(b, out) }
	case "PowerPoint Document":
		return func(b []byte, _ map[string][]byte, out *textBuffer) error { return extractPPTText(b, out) }
	}
	return nil
}

func readOLEStream(f *mscfb.File) ([]byte, error) {
	if f.Size > maxExtractorInputBytes {
		return nil, fmt.Errorf("stream exceeds %d-byte extractor limit", maxExtractorInputBytes)
	}
	b := make([]byte, f.Size)
	if _, err := f.ReadAt(b, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// walkOfficeStream emits the document text of a Word/Excel/PowerPoint main
// stream. It reports done=false when the stream could not be parsed so the
// caller scans the raw bytes instead (nothing is lost).
func (s *walkState) walkOfficeStream(entryName string, st oleStream, streams []oleStream, extract officeExtractor) (bool, error) {
	body, err := readOLEStream(st.file)
	if err != nil {
		s.partial("corrupt-entry", entryName, err)
		return false, nil
	}
	tables := map[string][]byte{}
	if st.path == "WordDocument" {
		for _, t := range streams {
			if t.path == "0Table" || t.path == "1Table" {
				if b, err := readOLEStream(t.file); err == nil {
					tables[t.path] = b
				}
			}
		}
	}
	out := &textBuffer{limit: s.extractLimit()}
	parseErr := extract(body, tables, out)
	if errors.Is(parseErr, errOfficeEncrypted) {
		s.partial("encrypted", entryName, parseErr)
		return true, nil
	}
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", entryName, fmt.Errorf("office text %w", errExtractLimit))
	}
	if parseErr != nil {
		s.partial("corrupt-entry", entryName, parseErr)
		if out.buf.Len() == 0 {
			return false, nil
		}
	}
	return true, s.emitDerived(entryName+extractedTextSuffix, out.buf.Bytes())
}

// walkWordStream emits the text of each Word story (main text, footnotes,
// headers, comments, endnotes, text boxes) as its own derived entry. It
// reports done=false when the stream could not be parsed so the caller
// scans the raw bytes instead, and the table stream it consumed otherwise.
func (s *walkState) walkWordStream(entryName string, st oleStream, streams []oleStream) (bool, string, error) {
	body, err := readOLEStream(st.file)
	if err != nil {
		s.partial("corrupt-entry", entryName, err)
		return false, "", nil
	}
	tables := map[string][]byte{}
	for _, t := range streams {
		if t.path == "0Table" || t.path == "1Table" {
			if b, err := readOLEStream(t.file); err == nil {
				tables[t.path] = b
			}
		}
	}
	out := &textBuffer{limit: s.extractLimit()}
	var marks []wordStoryMark
	parseErr := extractWordStories(body, tables, out, &marks)
	if errors.Is(parseErr, errOfficeEncrypted) {
		// RC4 CryptoAPI / Office binary encryption is not decrypted.
		s.partial("encrypted", entryName, parseErr)
		return true, "", nil
	}
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", entryName, fmt.Errorf("office text %w", errExtractLimit))
	}
	if parseErr != nil {
		s.partial("corrupt-entry", entryName, parseErr)
		if out.buf.Len() == 0 {
			return false, "", nil
		}
	}
	text := out.buf.Bytes()
	if len(marks) == 0 || marks[0].offset > 0 {
		marks = append([]wordStoryMark{{extractedTextSuffix, 0}}, marks...)
	}
	for i, m := range marks {
		end := len(text)
		if i+1 < len(marks) {
			end = marks[i+1].offset
		}
		if err := s.emitDerived(entryName+m.suffix, text[m.offset:end]); err != nil {
			return true, "", err
		}
	}
	return true, wordActiveTable(body), nil
}

// walkOle10Native unwraps an OLE Packager stream and walks the embedded
// file as a nested member (archives, Office files, and PDFs inside are
// expanded in turn). It reports done=false for malformed headers.
func (s *walkState) walkOle10Native(entryName string, st oleStream, depth int) (bool, error) {
	body, err := readOLEStream(st.file)
	if err != nil {
		return false, nil
	}
	name, payload, err := parseOle10Native(body)
	if err != nil {
		s.partial("corrupt-entry", entryName, err)
		return false, nil
	}
	clean := sanitizeComponent(name)
	return true, s.walkMember(entryName+"!"+clean, name, bytes.NewReader(payload), int64(len(payload)), depth)
}

// walkPropertySet emits the string properties of a summary information
// stream; malformed streams are scanned raw (done=false).
func (s *walkState) walkPropertySet(entryName string, st oleStream) (bool, error) {
	body, err := readOLEStream(st.file)
	if err != nil {
		return false, nil
	}
	out := &textBuffer{limit: s.extractLimit()}
	if err := extractPropertySetText(body, out); err != nil {
		s.partial("corrupt-entry", entryName, err)
		return false, nil
	}
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", entryName, fmt.Errorf("property set text %w", errExtractLimit))
	}
	return true, s.emitDerived(entryName+extractedTextSuffix, out.buf.Bytes())
}

func sanitizeOLEPath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = sanitizeComponent(part)
	}
	return strings.Join(parts, "/")
}

// hwpCompressedStream reports whether an HWP stream is deflated when the
// FileHeader compression flag is set (DocInfo, BodyText, BinData, scripts).
func hwpCompressedStream(p string) bool {
	switch {
	case p == "FileHeader", strings.HasPrefix(p, "\x05"), strings.HasPrefix(p, "PrvImage"), strings.HasPrefix(p, "PrvText"):
		return false
	}
	return true
}

// hwpInflater decodes raw deflate, or zlib when the stream carries a header.
func hwpInflater(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	if h, err := br.Peek(2); err == nil && h[0]&0x0f == 8 && (uint16(h[0])<<8|uint16(h[1]))%31 == 0 {
		if zr, err := zlib.NewReader(br); err == nil {
			return zr
		}
	}
	return flate.NewReader(br)
}

// walkHWPSection spools a (decompressed) BodyText section under the budget,
// then emits its paragraph text as UTF-8; the raw record stream is UTF-16
// interleaved with binary record headers and is not useful to detectors.
func (s *walkState) walkHWPSection(entryName, label string, input io.Reader, declared int64) error {
	value, accepted, err := s.expandedSpool(label, input, declared)
	if err != nil || !accepted {
		return err
	}
	defer func() {
		if cleanupErr := value.close(); cleanupErr != nil {
			s.partial("cleanup", entryName, cleanupErr)
		}
	}()
	body, ok := s.readForExtract(entryName, value)
	if !ok {
		return nil
	}
	out := &textBuffer{limit: s.extractLimit()}
	if err := extractHWPText(body, out); err != nil {
		s.partial("corrupt-entry", entryName, err)
	}
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", entryName, fmt.Errorf("HWP text %w", errExtractLimit))
	}
	return s.emitDerived(entryName+extractedTextSuffix, out.buf.Bytes())
}

// extractHWPText decodes HWPTAG_PARA_TEXT records. Control characters that
// occupy eight WCHARs (inline and extended controls) are skipped whole.
func extractHWPText(data []byte, out *textBuffer) error {
	for len(data) >= 4 {
		h := binary.LittleEndian.Uint32(data)
		data = data[4:]
		tag := h & 0x3ff
		size := int(h >> 20)
		if size == 0xfff {
			if len(data) < 4 {
				return errors.New("truncated HWP record size")
			}
			size = int(binary.LittleEndian.Uint32(data))
			data = data[4:]
		}
		if size < 0 || size > len(data) {
			return errors.New("HWP record out of range")
		}
		rec := data[:size]
		data = data[size:]
		if tag != hwpTagParaText {
			continue
		}
		var units []uint16
		for i := 0; i+1 < len(rec); i += 2 {
			c := binary.LittleEndian.Uint16(rec[i:])
			switch {
			case c == 10 || c == 13:
				units = append(units, '\n')
			case c == 0 || (c >= 24 && c <= 31):
			case c < 32:
				i += 14 // eight-WCHAR control: skip the remaining seven
			default:
				units = append(units, c)
			}
		}
		if len(units) == 0 {
			continue
		}
		if !out.writeString(strings.TrimRight(string(utf16.Decode(units)), "\n")) || !out.writeByte('\n') {
			return nil
		}
	}
	return nil
}
