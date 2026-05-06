package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// sample builds a deterministic Finding for golden tests. Centralised so the
// JSON / SARIF / Table assertions all share the same input shape.
func sample() engine.Finding {
	return engine.Finding{
		Detector: detectors.AWS,
		Result: detectors.Result{
			DetectorType: detectors.AWS,
			Verified:     true,
			Raw:          []byte("AKIAIOSFODNN7EXAMPLE"),
			Redacted:     "AKIA…AMPLE",
			ExtraData:    map[string]string{"account": "123456789012"},
		},
		Chunk: &sources.Chunk{
			SourceType: sources.SourceFilesystem,
			SourceName: "cli",
			Verify:     true,
			SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{
					Path: "/tmp/leak.txt",
					Line: 42,
				},
			},
		},
	}
}

func TestNewSinkRejectsUnknownFormat(t *testing.T) {
	if _, err := NewSink("yaml", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestJSONSinkEmitsArray(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("json", &buf)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, buf.String())
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	rec := got[0]
	if rec["detector"] != "AWS" {
		t.Errorf("detector: %v", rec["detector"])
	}
	if rec["verified"] != true {
		t.Errorf("verified: %v", rec["verified"])
	}
	if rec["redacted"] != "AKIA…AMPLE" {
		t.Errorf("redacted: %v", rec["redacted"])
	}
	src, _ := rec["source"].(map[string]any)
	if src["type"] != "filesystem" {
		t.Errorf("source.type: %v", src["type"])
	}
	md, _ := src["metadata"].(map[string]any)
	if md["path"] != "/tmp/leak.txt" {
		t.Errorf("metadata.path: %v", md["path"])
	}
}

func TestJSONSinkEmptyIsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("json", &buf)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Fatalf("want []\\n, got %q", buf.String())
	}
}

func TestJSONSinkVerificationError(t *testing.T) {
	f := sample()
	f.Result.Verified = false
	f.Result.VerificationErr = errors.New("network down")

	var buf bytes.Buffer
	s, _ := NewSink("json", &buf)
	s.Emit(f)
	_ = s.Close()

	var got []map[string]any
	_ = json.Unmarshal(buf.Bytes(), &got)
	if got[0]["verification_error"] != "network down" {
		t.Errorf("verification_error not propagated: %v", got[0])
	}
}

func TestSARIFSinkShape(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf)
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version: %v", doc["version"])
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "pleno-dlp" {
		t.Errorf("driver.name: %v", driver["name"])
	}
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0].(map[string]any)
	if r["ruleId"] != "AWS" {
		t.Errorf("ruleId: %v", r["ruleId"])
	}
	if r["level"] != "error" {
		t.Errorf("level: %v", r["level"])
	}
	locs := r["locations"].([]any)
	pl := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
	uri := pl["artifactLocation"].(map[string]any)["uri"]
	if uri != "/tmp/leak.txt" {
		t.Errorf("uri: %v", uri)
	}
	if pl["region"].(map[string]any)["startLine"].(float64) != 42 {
		t.Errorf("startLine: %v", pl["region"])
	}
}

func TestTableSinkColumns(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("table", &buf)
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "DETECTOR") || !strings.Contains(out, "VERIFIED") ||
		!strings.Contains(out, "LOCATION") || !strings.Contains(out, "REDACTED") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "AWS") {
		t.Errorf("missing detector row: %q", out)
	}
	if !strings.Contains(out, "/tmp/leak.txt:42") {
		t.Errorf("missing location: %q", out)
	}
	if !strings.Contains(out, "✓") {
		t.Errorf("expected verified glyph: %q", out)
	}
}

func TestTableSinkUnverifiedGlyph(t *testing.T) {
	tests := []struct {
		name   string
		verify bool
		ok     bool
		want   string
	}{
		{"verify-off", false, false, "?"},
		{"verify-on-fail", true, false, "✗"},
		{"verify-on-pass", true, true, "✓"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := sample()
			f.Chunk.Verify = tc.verify
			f.Result.Verified = tc.ok
			var buf bytes.Buffer
			s, _ := NewSink("table", &buf)
			s.Emit(f)
			_ = s.Close()
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("want %q in %q", tc.want, buf.String())
			}
		})
	}
}

func TestTableSinkEmptyOutput(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("table", &buf)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("zero findings should produce no output, got %q", buf.String())
	}
}
