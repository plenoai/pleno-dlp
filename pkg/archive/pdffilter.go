package archive

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
)

// PDF stream filters (PDF 32000-1:2008 §7.4): FlateDecode with PNG/TIFF
// predictors, LZWDecode, ASCII85Decode, ASCIIHexDecode, and RunLengthDecode,
// chained as listed in /Filter with per-filter /DecodeParms. Image-only
// filters (DCT, JPX, CCITTFax, JBIG2) and Crypt are not text and are left
// undecoded. Every stage is capped at pdfMaxStreamBytes.

var (
	pdfFilterKey     = regexp.MustCompile(`/Filter\s*`)
	pdfDecodeParmKey = regexp.MustCompile(`/(DecodeParms|DP)\s*`)
	pdfNameTok       = regexp.MustCompile(`^/([^\s/<>\[\]()]+)`)
	pdfNameAll       = regexp.MustCompile(`/([^\s/<>\[\]()]+)`)
	pdfParmRes       = map[string]*regexp.Regexp{}
	errPDFStreamCap  = errors.New("PDF stream exceeds decode cap")
)

func init() {
	for _, k := range []string{"EarlyChange", "Predictor", "Colors", "BitsPerComponent", "Columns"} {
		pdfParmRes[k] = regexp.MustCompile(`/` + k + `\s+(-?\d+)`)
	}
}

type pdfFilter struct {
	name  string
	parms []byte
}

// pdfFilters lists the filters of a stream dictionary in decode order.
func pdfFilters(dict []byte) []pdfFilter {
	loc := pdfFilterKey.FindIndex(dict)
	if loc == nil {
		return nil
	}
	var names []string
	rest := dict[loc[1]:]
	if arr := pdfBalanced(rest); len(arr) > 0 && arr[0] == '[' {
		for _, m := range pdfNameAll.FindAllSubmatch(arr, 16) {
			names = append(names, string(m[1]))
		}
	} else if m := pdfNameTok.FindSubmatch(rest); m != nil {
		names = append(names, string(m[1]))
	}
	parms := make([][]byte, len(names))
	if loc := pdfDecodeParmKey.FindIndex(dict); loc != nil {
		v := pdfBalanced(dict[loc[1]:])
		switch {
		case len(v) > 1 && v[0] == '<':
			if len(parms) > 0 {
				parms[0] = v
			}
		case len(v) > 0 && v[0] == '[':
			// Array of dictionaries or null, one per filter.
			body := v[1:]
			for i := 0; i < len(parms); i++ {
				body = bytes.TrimLeft(body, " \t\r\n\f")
				if bytes.HasPrefix(body, []byte("null")) {
					body = body[4:]
					continue
				}
				d := pdfBalanced(body)
				if len(d) == 0 || d[0] != '<' {
					break
				}
				parms[i] = d
				body = body[len(d):]
			}
		}
	}
	out := make([]pdfFilter, len(names))
	for i, n := range names {
		out[i] = pdfFilter{name: n, parms: parms[i]}
	}
	return out
}

// pdfDecodeStream applies the stream's filters. ok is false when a filter is
// not a text-capable one, in which case the stream is not text.
func pdfDecodeStream(dict, raw []byte) (data []byte, ok bool, err error) {
	data = raw
	for _, f := range pdfFilters(dict) {
		var stageErr error
		switch f.name {
		case "FlateDecode", "Fl":
			data, stageErr = pdfInflate(data)
			if len(data) > 0 {
				var perr error
				data, perr = pdfPredict(data, f.parms)
				stageErr = errors.Join(stageErr, perr)
			}
		case "LZWDecode", "LZW":
			early := 1
			if v, ok := pdfParmInt(f.parms, "EarlyChange"); ok {
				early = v
			}
			data, stageErr = pdfLZW(data, early != 0)
			if len(data) > 0 {
				var perr error
				data, perr = pdfPredict(data, f.parms)
				stageErr = errors.Join(stageErr, perr)
			}
		case "ASCII85Decode", "A85":
			data, stageErr = pdfASCII85(data)
		case "ASCIIHexDecode", "AHx":
			data = pdfASCIIHex(data)
		case "RunLengthDecode", "RL":
			data, stageErr = pdfRunLength(data)
		default:
			return nil, false, nil
		}
		if stageErr != nil {
			err = errors.Join(err, stageErr)
			if len(data) == 0 {
				return nil, true, err
			}
		}
	}
	return data, true, err
}

func pdfParmInt(parms []byte, key string) (int, bool) {
	re := pdfParmRes[key]
	if re == nil {
		return 0, false
	}
	m := re.FindSubmatch(parms)
	if m == nil {
		return 0, false
	}
	v, err := strconv.Atoi(string(m[1]))
	return v, err == nil
}

// pdfPredict reverses a PNG (10-15) or TIFF (2) predictor.
func pdfPredict(data, parms []byte) ([]byte, error) {
	pred, _ := pdfParmInt(parms, "Predictor")
	if pred <= 1 {
		return data, nil
	}
	colors, bpc, columns := 1, 8, 1
	if v, ok := pdfParmInt(parms, "Colors"); ok {
		colors = v
	}
	if v, ok := pdfParmInt(parms, "BitsPerComponent"); ok {
		bpc = v
	}
	if v, ok := pdfParmInt(parms, "Columns"); ok {
		columns = v
	}
	if colors < 1 || colors > 32 || bpc < 1 || bpc > 16 || columns < 1 || columns > 1<<20 {
		return data, errors.New("PDF predictor parameters out of range")
	}
	bpp := max(1, (colors*bpc+7)/8)
	row := (colors*bpc*columns + 7) / 8
	if pred == 2 {
		if bpc != 8 {
			return data, errors.New("TIFF predictor supports 8-bit components only")
		}
		out := append([]byte(nil), data...)
		for r := 0; r+row <= len(out); r += row {
			for i := bpp; i < row; i++ {
				out[r+i] += out[r+i-bpp]
			}
		}
		return out, nil
	}
	if pred < 10 {
		return data, errors.New("unknown PDF predictor")
	}
	out := make([]byte, 0, len(data))
	prev := make([]byte, row)
	for p := 0; p < len(data); p += row + 1 {
		if p+1 > len(data) {
			break
		}
		typ := data[p]
		cur := make([]byte, row)
		copy(cur, data[p+1:min(len(data), p+1+row)])
		for i := 0; i < row; i++ {
			var left, upLeft byte
			if i >= bpp {
				left, upLeft = cur[i-bpp], prev[i-bpp]
			}
			up := prev[i]
			switch typ {
			case 0:
			case 1:
				cur[i] += left
			case 2:
				cur[i] += up
			case 3:
				cur[i] += byte((int(left) + int(up)) / 2)
			case 4:
				cur[i] += paeth(left, up, upLeft)
			default:
				return out, errors.New("bad PNG predictor row type")
			}
		}
		out = append(out, cur...)
		prev = cur
	}
	return out, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := absInt(p-int(a)), absInt(p-int(b)), absInt(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// pdfLZW decodes PDF LZW (MSB-first, 9-12 bit codes, 256 clear, 257 EOD).
// With early change the code width grows one code earlier, as in TIFF.
func pdfLZW(data []byte, early bool) ([]byte, error) {
	const clear, eod = 256, 257
	var out []byte
	prefix := make([]int32, 4096)
	suffix := make([]byte, 4096)
	length := make([]int32, 4096)
	for i := 0; i < 256; i++ {
		prefix[i], suffix[i], length[i] = -1, byte(i), 1
	}
	next, width, prev := 258, 9, -1
	var acc uint32
	bits := 0
	shift := 0
	if early {
		shift = 1
	}
	emit := func(code int) []byte {
		n := int(length[code])
		start := len(out)
		out = append(out, make([]byte, n)...)
		for c, i := code, start+n-1; c >= 0 && i >= start; c, i = int(prefix[c]), i-1 {
			out[i] = suffix[c]
		}
		return out[start:]
	}
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= width {
			code := int(acc>>(bits-width)) & (1<<width - 1)
			bits -= width
			switch {
			case code == clear:
				next, width, prev = 258, 9, -1
				continue
			case code == eod:
				return out, nil
			case prev < 0:
				if code > 255 {
					return out, errors.New("PDF LZW: bad first code")
				}
				emit(code)
			case code < next:
				s := emit(code)
				if next < 4096 {
					prefix[next], suffix[next], length[next] = int32(prev), s[0], length[prev]+1
					next++
				}
			case code == next && next < 4096:
				first := out[len(out)-int(length[prev])]
				prefix[next], suffix[next], length[next] = int32(prev), first, length[prev]+1
				next++
				emit(code)
			default:
				return out, errors.New("PDF LZW: code out of range")
			}
			prev = code
			if len(out) > pdfMaxStreamBytes {
				return out[:pdfMaxStreamBytes], errPDFStreamCap
			}
			if next+shift >= 1<<width && width < 12 {
				width++
			}
		}
	}
	return out, nil
}

func pdfASCII85(data []byte) ([]byte, error) {
	var out []byte
	var group [5]byte
	n := 0
	data = bytes.TrimPrefix(bytes.TrimLeft(data, " \t\r\n\f"), []byte("<~"))
	for _, c := range data {
		switch {
		case c == '~':
			goto done
		case c == 'z' && n == 0:
			out = append(out, 0, 0, 0, 0)
		case c >= '!' && c <= 'u':
			group[n] = c - '!'
			n++
			if n == 5 {
				var v uint32
				for _, d := range group {
					v = v*85 + uint32(d)
				}
				out = append(out, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
				n = 0
			}
		case c <= ' ':
		default:
			return out, errors.New("PDF ASCII85: invalid character")
		}
		if len(out) > pdfMaxStreamBytes {
			return out[:pdfMaxStreamBytes], errPDFStreamCap
		}
	}
done:
	if n > 1 {
		for i := n; i < 5; i++ {
			group[i] = 84
		}
		var v uint32
		for _, d := range group {
			v = v*85 + uint32(d)
		}
		b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		out = append(out, b[:n-1]...)
	}
	return out, nil
}

func pdfASCIIHex(data []byte) []byte {
	if i := bytes.IndexByte(data, '>'); i >= 0 {
		data = data[:i]
	}
	return pdfHex(data)
}

func pdfRunLength(data []byte) ([]byte, error) {
	var out []byte
	for i := 0; i < len(data); {
		l := int(data[i])
		i++
		switch {
		case l == 128:
			return out, nil
		case l < 128:
			if i+l+1 > len(data) {
				return append(out, data[i:]...), errors.New("PDF RunLength: truncated literal run")
			}
			out = append(out, data[i:i+l+1]...)
			i += l + 1
		default:
			if i >= len(data) {
				return out, errors.New("PDF RunLength: truncated repeat run")
			}
			out = append(out, bytes.Repeat(data[i:i+1], 257-l)...)
			i++
		}
		if len(out) > pdfMaxStreamBytes {
			return out[:pdfMaxStreamBytes], errPDFStreamCap
		}
	}
	return out, nil
}
