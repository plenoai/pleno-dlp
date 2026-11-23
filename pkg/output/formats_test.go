package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/report"
)

func TestJSONLSinkOneRecordPerLine(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("jsonl", &buf, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(sample())
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line not JSON: %v", err)
		}
		if rec["detector"] != "AWS" || rec["secret_hash"] == "" {
			t.Errorf("unexpected record: %v", rec)
		}
	}
	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("jsonl leaked raw secret")
	}
	// Round-trips through the viewer importer.
	fs, err := report.Import(&buf, "x.jsonl")
	if err != nil || len(fs) != 2 || fs[0].File != "/tmp/leak.txt" || fs[0].Line != 42 {
		t.Fatalf("import: %v %+v", err, fs)
	}
}

func TestHTMLSinkSelfContainedAndRedacted(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("html", &buf, "v9")
	if err != nil {
		t.Fatal(err)
	}
	f := sample()
	f.Result.Redacted = "<script>alert(1)</script>"
	s.Emit(f)
	s.Emit(f) // duplicate collapses
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("html leaked raw secret")
	}
	if strings.Contains(out, "<script>alert(1)") {
		t.Fatal("redacted display not escaped")
	}
	for _, bad := range []string{"src=\"http", "href=\"http", "<link"} {
		if strings.Contains(out, bad) {
			t.Fatalf("html references external resource %q", bad)
		}
	}
	if !strings.Contains(out, "1 finding(s)") || !strings.Contains(out, "/tmp/leak.txt:42") {
		t.Fatalf("missing content:\n%s", out)
	}
}
