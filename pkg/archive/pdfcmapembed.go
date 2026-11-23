package archive

import (
	"regexp"
	"strconv"
	"strings"
)

// Embedded CMap streams (PDF 32000-1:2008 §9.7.5.3) give a Type0 font's
// byte -> CID encoding inline. They commonly inherit a predefined CJK CMap
// with /UseCMap (in the stream dictionary or as the "usecmap" operator) and
// add local cidchar/cidrange overrides. Without /ToUnicode the CIDs are
// decoded through the base CMap's ordering table, or the ordering the CMap
// or the descendant font declares (#959).

var (
	pdfEncodingRef = regexp.MustCompile(`/Encoding\s+(\d+)\s+\d+\s+R`)
	pdfUseCMapName = regexp.MustCompile(`/UseCMap\s*/([A-Za-z0-9.+_-]+)`)
	pdfUseCMapRef  = regexp.MustCompile(`/UseCMap\s+(\d+)\s+\d+\s+R`)
)

const (
	pdfMaxEmbeddedCMapDepth   = 4
	pdfMaxEmbeddedCMapEntries = 1 << 17
)

// pdfType0EmbeddedCMap builds a decoder for a Type0 font whose /Encoding is
// an embedded CMap stream; nil when it maps no CIDs or no ordering applies.
func pdfType0EmbeddedCMap(fontDict []byte, objs map[int]*pdfObject) pdfFont {
	m := pdfEncodingRef.FindSubmatch(fontDict)
	if m == nil {
		return nil
	}
	num, _ := strconv.Atoi(string(m[1]))
	cm, ordering := pdfEmbeddedCMap(objs, num, 0)
	if cm == nil || len(cm.cids) == 0 {
		return nil
	}
	if ordering == "" {
		if info := pdfValueAfter(pdfDescendantDict(fontDict, objs), pdfCIDSystemInfo, objs); info != nil {
			ordering = pdfAdobeOrdering(info)
		}
	}
	table := cidOrderingTable(ordering)
	if table == nil {
		return nil
	}
	return &pdfPredefFont{cmap: cm, table: table}
}

func pdfAdobeOrdering(info []byte) string {
	reg := pdfRegistryRe.FindSubmatch(info)
	ord := pdfOrderingRe.FindSubmatch(info)
	if reg == nil || ord == nil || string(reg[1]) != "Adobe" {
		return ""
	}
	return string(ord[1])
}

// pdfEmbeddedCMap parses CMap stream num on top of its /UseCMap base and
// returns the merged table plus the character collection ordering.
func pdfEmbeddedCMap(objs map[int]*pdfObject, num, depth int) (*predefCMap, string) {
	o := objs[num]
	if o == nil || !o.hasStream || depth >= pdfMaxEmbeddedCMapDepth {
		return nil, ""
	}
	data := o.stream
	if len(data) > pdfMaxCMapBytes {
		data = data[:pdfMaxCMapBytes]
	}
	toks := cmapTokens(data)
	cm := &predefCMap{cids: map[uint64]uint16{}}
	ordering := ""
	inherit := func(base *predefCMap, ord string) {
		if base == nil {
			return
		}
		// Copy (predefined tables are shared through the cache) without
		// replacing local definitions that precede a late usecmap.
		for k, v := range base.cids {
			if _, ok := cm.cids[k]; !ok {
				cm.cids[k] = v
			}
		}
		for i, n := range base.lens {
			cm.lens[i] = max(cm.lens[i], n)
		}
		if ordering == "" {
			ordering = ord
		}
	}
	useName := func(name string) {
		if column, _, ok := predefCMapColumn(name); ok {
			inherit(loadPredefCMap(name), predefinedCMapOrdering[column])
		}
	}
	if u := pdfUseCMapName.FindSubmatch(o.dict); u != nil {
		useName(string(u[1]))
	} else if u := pdfUseCMapRef.FindSubmatch(o.dict); u != nil {
		ref, _ := strconv.Atoi(string(u[1]))
		inherit(pdfEmbeddedCMap(objs, ref, depth+1))
	}
	if ordering == "" {
		ordering = pdfAdobeOrdering(o.dict)
	}
	if ordering == "" {
		ordering = pdfAdobeOrdering(data)
	}
	mode := ""
	for i := 0; i < len(toks) && len(cm.cids) < pdfMaxEmbeddedCMapEntries; i++ {
		t := string(toks[i])
		switch t {
		case "usecmap":
			// The tokenizer drops the name's "/" delimiter.
			if i > 0 {
				useName(strings.TrimPrefix(string(toks[i-1]), "/"))
			}
			continue
		case "begincodespacerange", "begincidchar", "begincidrange":
			mode = t
			continue
		case "endcodespacerange", "endcidchar", "endcidrange":
			mode = ""
			continue
		}
		switch mode {
		case "begincodespacerange":
			if i+1 < len(toks) && isHexTok(toks[i]) && isHexTok(toks[i+1]) {
				lo, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
				hi, n2 := pdfHexCode(toks[i+1][1 : len(toks[i+1])-1])
				if n > 0 && n == n2 && lo <= hi {
					shift := 8 * (n - 1)
					for b := lo >> shift; b <= hi>>shift && b < 256; b++ {
						cm.lens[b] = max(cm.lens[b], uint8(n))
					}
				}
				i++
			}
		case "begincidchar":
			if i+1 < len(toks) && isHexTok(toks[i]) {
				code, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
				if cid, err := strconv.ParseUint(string(toks[i+1]), 10, 16); err == nil && n > 0 {
					cm.set(code, n, uint16(cid))
				}
				i++
			}
		case "begincidrange":
			if i+2 < len(toks) && isHexTok(toks[i]) && isHexTok(toks[i+1]) {
				lo, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
				hi, n2 := pdfHexCode(toks[i+1][1 : len(toks[i+1])-1])
				cid, err := strconv.ParseUint(string(toks[i+2]), 10, 16)
				if err == nil && n > 0 && n == n2 && lo <= hi && hi-lo < 1<<16 && cid+uint64(hi-lo) < 1<<16 {
					for c := lo; c <= hi && len(cm.cids) < pdfMaxEmbeddedCMapEntries; c++ {
						cm.set(c, n, uint16(cid+uint64(c-lo)))
					}
				}
				i += 2
			}
		}
	}
	return cm, ordering
}

// set maps one n-byte code to cid and records its lead byte's length.
func (t *predefCMap) set(code uint32, n int, cid uint16) {
	t.cids[uint64(n)<<32|uint64(code)] = cid
	if lead := byte(code >> (8 * (n - 1))); uint8(n) > t.lens[lead] {
		t.lens[lead] = uint8(n)
	}
}
