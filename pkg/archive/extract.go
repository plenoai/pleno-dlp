package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Content extractors turn structured binary formats (SQLite databases, PDF
// documents, Python bytecode, Office XML parts) into scannable text. Unlike
// container walkers they do not recurse: each produces derived leaf entries
// whose bytes are charged against the same expansion budget as decompressed
// archive members.

const (
	// extractedTextSuffix names the single derived entry of a text extractor.
	extractedTextSuffix = "#text"
	// maxExtractorInputBytes bounds how much of one structured file an
	// extractor parses in memory. Entries are already capped by
	// MaxEntryBytes/MaxInputBytes; this is a format-independent ceiling.
	maxExtractorInputBytes = 64 << 20
)

var errExtractLimit = errors.New("extracted text exceeds budget")

// textBuffer collects extractor output up to a hard limit. Writes past the
// limit are dropped and reported once through errExtractLimit so callers can
// record a coverage gap instead of silently truncating.
type textBuffer struct {
	buf      bytes.Buffer
	limit    int64
	overflow bool
}

func (b *textBuffer) write(p []byte) bool {
	if b.overflow {
		return false
	}
	if int64(b.buf.Len())+int64(len(p)) > b.limit {
		b.overflow = true
		return false
	}
	b.buf.Write(p)
	return true
}

func (b *textBuffer) writeString(s string) bool { return b.write([]byte(s)) }
func (b *textBuffer) writeByte(c byte) bool     { return b.write([]byte{c}) }

// extractLimit is the most derived text one extractor may produce.
func (s *walkState) extractLimit() int64 {
	limit := s.limits.MaxEntryBytes
	if remaining := s.limits.MaxExpandedBytes - s.expanded; remaining < limit {
		limit = remaining
	}
	if limit < 0 {
		limit = 0
	}
	return limit
}

// readForExtract loads one structured file for an in-memory parser.
func (s *walkState) readForExtract(name string, data *spool) ([]byte, bool) {
	if data.size > maxExtractorInputBytes {
		s.partial("max-entry-bytes", name, fmt.Errorf("structured file exceeds %d-byte extractor limit", maxExtractorInputBytes))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(contextReader{ctx: s.ctx, r: data.reader()}, data.size))
	if err != nil {
		s.partial("corrupt-entry", name, err)
		return nil, false
	}
	return body, true
}

// emitDerived charges body against the expansion budget and emits it as a
// leaf entry.
func (s *walkState) emitDerived(name string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	value, accepted, err := s.expandedSpool(name, bytes.NewReader(body), int64(len(body)))
	if err != nil || !accepted {
		return err
	}
	emitErr := s.emitEntry(name, value)
	if cleanupErr := value.close(); cleanupErr != nil {
		s.partial("cleanup", name, cleanupErr)
	}
	return emitErr
}

type textExtractor func(data []byte, out *textBuffer) error

// walkExtracted runs a text extractor. A parse failure records a coverage
// gap and falls back to scanning the raw bytes so no content is lost; text
// recovered before the failure is still emitted.
func (s *walkState) walkExtracted(name string, data *spool, format string, extract textExtractor) error {
	body, ok := s.readForExtract(name, data)
	if !ok {
		return s.emitEntry(name, data)
	}
	out := &textBuffer{limit: s.extractLimit()}
	parseErr := extract(body, out)
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", name, fmt.Errorf("%s %w", format, errExtractLimit))
	}
	if parseErr != nil {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		s.partial("corrupt-entry", name, fmt.Errorf("%s: %w", format, parseErr))
		if out.buf.Len() == 0 {
			return s.emitEntry(name, data)
		}
	}
	return s.emitDerived(name+extractedTextSuffix, out.buf.Bytes())
}

// officeXMLPart reports whether a ZIP member holds Office/ODF document text
// whose runs are split across XML tags (w:t, a:t, sharedStrings, text:p).
func officeXMLPart(name string) bool {
	i := strings.LastIndexByte(name, '!')
	if i < 0 {
		return false
	}
	inner := name[i+1:]
	if !strings.HasSuffix(inner, ".xml") {
		return false
	}
	switch {
	case strings.HasPrefix(inner, "word/"), strings.HasPrefix(inner, "ppt/"), strings.HasPrefix(inner, "xl/"):
		return !strings.Contains(inner, "/_rels/") && !strings.HasPrefix(path.Base(inner), "theme")
	case inner == "content.xml", inner == "styles.xml":
		return true
	}
	return false
}

// paragraphEndTags end a logical text line in WordprocessingML, DrawingML,
// SpreadsheetML shared strings/rows, and ODF.
var paragraphEndTags = []string{"w:p", "a:p", "si", "row", "text:p", "text:h", "w:tab", "w:br", "a:br", "c", "table:table-row"}

// extractOfficeXMLText strips markup so text runs split across tags are
// rejoined, emitting one line per paragraph. Attribute values are dropped;
// the raw member is still scanned separately.
func extractOfficeXMLText(data []byte, out *textBuffer) error {
	var line bytes.Buffer
	flush := func() bool {
		text := bytes.TrimSpace(line.Bytes())
		line.Reset()
		if len(text) == 0 {
			return true
		}
		return out.write(text) && out.writeByte('\n')
	}
	for i := 0; i < len(data); {
		c := data[i]
		if c != '<' {
			j := bytes.IndexByte(data[i:], '<')
			if j < 0 {
				j = len(data) - i
			}
			line.Write(unescapeXML(data[i : i+j]))
			i += j
			continue
		}
		end := bytes.IndexByte(data[i:], '>')
		if end < 0 {
			break
		}
		tag := data[i+1 : i+end]
		i += end + 1
		if len(tag) == 0 || tag[0] == '?' || tag[0] == '!' {
			continue
		}
		closing := tag[0] == '/'
		if closing {
			tag = tag[1:]
		}
		selfClosing := bytes.HasSuffix(tag, []byte("/"))
		nameEnd := bytes.IndexAny(tag, " \t\r\n/")
		if nameEnd < 0 {
			nameEnd = len(tag)
		}
		tagName := string(tag[:nameEnd])
		if !closing && !selfClosing {
			continue
		}
		for _, end := range paragraphEndTags {
			if tagName == end {
				switch tagName {
				case "w:tab", "c":
					line.WriteByte('\t')
				default:
					if !flush() {
						return nil
					}
				}
				break
			}
		}
	}
	flush()
	return nil
}

var xmlEntities = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")

func unescapeXML(b []byte) []byte {
	if bytes.IndexByte(b, '&') < 0 {
		return b
	}
	return []byte(xmlEntities.Replace(string(b)))
}

// emitOfficeText adds a derived plain-text entry for an Office XML part.
func (s *walkState) emitOfficeText(name string, data *spool) error {
	body, ok := s.readForExtract(name, data)
	if !ok {
		return nil
	}
	out := &textBuffer{limit: s.extractLimit()}
	_ = extractOfficeXMLText(body, out)
	if out.overflow {
		s.rejectBudget("max-expanded-bytes", name, fmt.Errorf("office text %w", errExtractLimit))
	}
	return s.emitDerived(name+extractedTextSuffix, out.buf.Bytes())
}

// sanitizeComponent makes an extractor-chosen label safe as a path component.
func sanitizeComponent(label string) string {
	label = strings.Map(func(r rune) rune {
		switch {
		case r == '/', r == '\\', r == '!', r == 0:
			return '_'
		case r < 0x20:
			return '_'
		}
		return r
	}, label)
	if label == "" || label == "." || label == ".." {
		return "_"
	}
	return label
}
