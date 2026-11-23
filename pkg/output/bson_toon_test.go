package output

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// readBSONStrings walks one top-level BSON document and returns its string
// and bool fields; nested docs are skipped by length.
func readBSONStrings(t *testing.T, doc []byte) map[string]string {
	t.Helper()
	if int(binary.LittleEndian.Uint32(doc)) != len(doc) || doc[len(doc)-1] != 0 {
		t.Fatalf("bad doc framing")
	}
	out := map[string]string{}
	i := 4
	for doc[i] != 0 {
		typ := doc[i]
		i++
		end := bytes.IndexByte(doc[i:], 0)
		key := string(doc[i : i+end])
		i += end + 1
		switch typ {
		case 0x02:
			n := int(binary.LittleEndian.Uint32(doc[i:]))
			out[key] = string(doc[i+4 : i+4+n-1])
			i += 4 + n
		case 0x08:
			out[key] = map[byte]string{0: "false", 1: "true"}[doc[i]]
			i++
		case 0x03, 0x04:
			i += int(binary.LittleEndian.Uint32(doc[i:]))
		case 0x12, 0x01:
			i += 8
		case 0x0A:
		default:
			t.Fatalf("unexpected type %#x", typ)
		}
	}
	return out
}

func TestBSONSinkConcatenatedDocuments(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("bson", &buf, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(sample())
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	n := int(binary.LittleEndian.Uint32(b))
	first := readBSONStrings(t, b[:n])
	second := readBSONStrings(t, b[n:])
	if first["detector"] != "AWS" || first["verdict"] == "" || second["fingerprint"] != first["fingerprint"] {
		t.Fatalf("unexpected docs: %v / %v", first, second)
	}
	if bytes.Contains(b, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatal("bson leaked raw secret")
	}
}

func TestTOONSinkTabular(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("toon", &buf, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	f := sample()
	f.Result.Redacted = "a,b"
	s.Emit(f)
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "findings[2]{detector,severity,verdict,redacted,location,fingerprint}:\n") {
		t.Fatalf("missing header: %s", out)
	}
	if !strings.Contains(out, `"a,b"`) || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("quoting/redaction wrong: %s", out)
	}
	empty := &bytes.Buffer{}
	e, _ := NewSink("toon", empty, "")
	_ = e.Close()
	if !strings.Contains(empty.String(), "findings[0]") {
		t.Fatalf("empty: %s", empty)
	}
}

func TestTOONValueQuoting(t *testing.T) {
	for in, want := range map[string]string{"AWS": "AWS", "": `""`, "true": `"true"`, "42": `"42"`, "a:b": `"a:b"`, " x": `" x"`, "-1": `"-1"`} {
		if got := toonValue(in); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}
