package decoder

import (
	"math/rand"
	"reflect"
	"testing"
)

type base64Emit struct {
	run      string
	alphabet byte
}

// linearBase64Spans is the byte-at-a-time definition walkBase64Spans must
// reproduce.
func linearBase64Spans(data []byte) ([]byteSpan, []base64Emit) {
	var spans []byteSpan
	var out []base64Emit
	start := -1
	var alphabet byte
	flush := func(end int) {
		if end-start >= minBase64Run {
			if end-start >= minHexRun {
				spans = append(spans, byteSpan{start, end})
			}
			pad := 0
			for pad < 2 && end+pad < len(data) && data[end+pad] == '=' {
				pad++
			}
			out = append(out, base64Emit{string(data[start : end+pad]), alphabet})
		}
	}
	for i, c := range data {
		if byteClass[c]&classBase64 != 0 {
			if start < 0 {
				start, alphabet = i, 0
			}
			switch c {
			case '-', '_':
				alphabet = 1
			case '+', '/':
				alphabet = 0
			}
			continue
		}
		if start >= 0 {
			flush(i)
			start = -1
		}
	}
	if start >= 0 {
		flush(len(data))
	}
	return spans, out
}

func TestWalkBase64SpansMatchesLinearWalk(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	alphabet := []byte("aZ09-_+/= .\n")
	for iter := 0; iter < 20000; iter++ {
		b := make([]byte, rng.Intn(300))
		sep := 2 + rng.Intn(60)
		for i := range b {
			if rng.Intn(sep) == 0 {
				b[i] = alphabet[8+rng.Intn(4)]
			} else {
				b[i] = alphabet[rng.Intn(8)]
			}
		}
		var spans []byteSpan
		var got []base64Emit
		walkBase64Spans(b, &spans, func(run []byte, a byte) { got = append(got, base64Emit{string(run), a}) })
		wantSpans, want := linearBase64Spans(b)
		if !reflect.DeepEqual(spans, wantSpans) || !reflect.DeepEqual(got, want) {
			t.Fatalf("%q:\n got %v %v\nwant %v %v", b, spans, got, wantSpans, want)
		}
	}
}
