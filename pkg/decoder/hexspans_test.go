package decoder

import (
	"bytes"
	"strings"
	"testing"
)

// hexFromBase64Spans decodes hex the way VariantsWithScratch does: only
// inside the base64-alphabet spans recorded by the base64 pass.
func hexFromBase64Spans(data []byte) []byte {
	var spans []byteSpan
	walkBase64Spans(data, &spans, func([]byte, byte) {})
	return decodeHexSpans(data, spans)
}

func TestHexSpansMatchFullWalk(t *testing.T) {
	hexRun := strings.Repeat("68656c6c6f20776f726c64", 4) // "hello world" x4
	for _, in := range []string{
		"",
		hexRun,
		"x=" + hexRun + ";",
		"abc_" + hexRun + "-zz " + hexRun,
		"++" + hexRun + "==" + hexRun,
		strings.Repeat("A", 31) + hexRun,
		"g" + hexRun[:39] + "g",
	} {
		data := []byte(in)
		if got, want := hexFromBase64Spans(data), decodeHex(data); !bytes.Equal(got, want) {
			t.Errorf("hex spans for %q = %q, full walk = %q", in, got, want)
		}
	}
}

func FuzzHexSpansMatchFullWalk(f *testing.F) {
	f.Add([]byte("k=" + strings.Repeat("6869", 30) + "/x"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, want := hexFromBase64Spans(data), decodeHex(data); !bytes.Equal(got, want) {
			t.Fatalf("hex spans for %q = %q, full walk = %q", data, got, want)
		}
	})
}
