package decoder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestStreamSourceSpansMatchesSourceSpan pins #977: a token found in a
// streamed variant maps to the same encoded bytes SourceSpan reports for the
// buffered variant.
func TestStreamSourceSpansMatchesSourceSpan(t *testing.T) {
	const token = "ghp_streamSpanToken0123456789abcdefABCD"
	utf16le := func(s string) []byte {
		var b bytes.Buffer
		for _, u := range utf16.Encode([]rune(s)) {
			b.WriteByte(byte(u))
			b.WriteByte(byte(u >> 8))
		}
		return b.Bytes()
	}
	unicodeEsc := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			b.WriteString(`\u00`)
			b.WriteString(hex.EncodeToString([]byte{byte(r)}))
		}
		return b.String()
	}
	cases := map[string][]byte{
		"base64":         []byte("line one\nline two " + base64.StdEncoding.EncodeToString([]byte("prefix ok "+token+" suffix")) + "\n" + base64.StdEncoding.EncodeToString([]byte("second run "+token+" again")) + "\n"),
		"hex":            []byte("a\nb\nkey=" + hex.EncodeToString([]byte("value "+token+" end")) + "\n"),
		"percent":        []byte("x=1\n%41%42 q=" + url.QueryEscape("a b "+token+" c") + "\n"),
		"unicode-escape": []byte("{\n\"k\": \"" + unicodeEsc("pre "+token) + "\"\n}\n"),
		"utf16le":        append([]byte{0xFF, 0xFE}, utf16le("hello\nworld "+token+"\nbye\n")...),
	}
	for source, data := range cases {
		t.Run(source, func(t *testing.T) {
			var buffered []byte
			for _, v := range Variants(data) {
				if v.Source == source {
					buffered = v.Data
				}
			}
			if buffered == nil {
				t.Fatalf("no buffered %s variant", source)
			}
			bi := bytes.Index(buffered, []byte(token))
			ws, we, ok := SourceSpan(source, data, bi, bi+len(token))
			if bi < 0 || !ok {
				t.Fatalf("buffered SourceSpan failed: idx=%d ok=%v", bi, ok)
			}
			var streamed []byte
			err := WalkVariants(context.Background(), bytes.NewReader(data), int64(len(data)), func(s string, r io.ReaderAt, n int64) error {
				if s == source {
					streamed = make([]byte, n)
					_, err := r.ReadAt(streamed, 0)
					return err
				}
				return nil
			})
			if err != nil || streamed == nil {
				t.Fatalf("walk: %v (variant found %v)", err, streamed != nil)
			}
			si := int64(bytes.Index(streamed, []byte(token)))
			spans, oks, err := StreamSourceSpans(context.Background(), bytes.NewReader(data), int64(len(data)), source,
				[][2]int64{{si, si + int64(len(token))}, {-1, 0}, {si + 1, si + 2}})
			if err != nil {
				t.Fatal(err)
			}
			if !oks[0] || spans[0] != [2]int64{int64(ws), int64(we)} {
				t.Fatalf("stream span = %v ok=%v, want [%d %d]", spans[0], oks[0], ws, we)
			}
			if oks[1] {
				t.Fatalf("invalid span mapped: %v", spans[1])
			}
			if !oks[2] || spans[2][0] < spans[0][0] || spans[2][1] > spans[0][1] {
				t.Fatalf("interior span %v outside %v", spans[2], spans[0])
			}
		})
	}
}

func TestStreamSourceSpansUnknownSource(t *testing.T) {
	_, oks, err := StreamSourceSpans(context.Background(), bytes.NewReader([]byte("abc")), 3, "", [][2]int64{{0, 1}})
	if err != nil || oks[0] {
		t.Fatalf("raw source mapped: ok=%v err=%v", oks[0], err)
	}
}
