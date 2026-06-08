package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
			Severity:     detectors.SeverityCritical,
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
	if _, err := NewSink("yaml", &bytes.Buffer{}, "test"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestJSONSinkEmitsArray(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("json", &buf, "test")
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
	wantHash := sha256Hex("AKIAIOSFODNN7EXAMPLE")
	if rec["secret_hash"] != wantHash {
		t.Errorf("secret_hash: %v, want %s", rec["secret_hash"], wantHash)
	}
	if _, ok := rec["secret_hash_v2"]; ok {
		t.Errorf("secret_hash_v2 should be omitted when RawV2 is empty: %v", rec)
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

func TestJSONSinkEmitsRawV2Hash(t *testing.T) {
	f := sample()
	f.Result.RawV2 = []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYqWERTY1KEY")

	var buf bytes.Buffer
	s, err := NewSink("json", &buf, "test")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	s.Emit(f)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, buf.String())
	}
	if got[0]["secret_hash_v2"] != sha256Hex(string(f.Result.RawV2)) {
		t.Errorf("secret_hash_v2: %v", got[0]["secret_hash_v2"])
	}
}

func TestJSONSinkEmitsGitHubLink(t *testing.T) {
	f := sample()
	f.Chunk.SourceType = sources.SourceGitHub
	f.Chunk.SourceMetadata = sources.Metadata{
		GitHub: &sources.GitHubMeta{
			Repository: "owner/repo",
			Link:       "https://github.com/owner/repo/pull/1#discussion_r1",
			File:       "app/config.go",
			Line:       12,
		},
	}

	var buf bytes.Buffer
	s, err := NewSink("json", &buf, "test")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	s.Emit(f)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, buf.String())
	}
	src, _ := got[0]["source"].(map[string]any)
	md, _ := src["metadata"].(map[string]any)
	if md["link"] != "https://github.com/owner/repo/pull/1#discussion_r1" {
		t.Errorf("metadata.link: %v", md["link"])
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestJSONSinkEmptyIsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("json", &buf, "test")
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
	s, _ := NewSink("json", &buf, "test")
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
	s, _ := NewSink("sarif", &buf, "test")
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

func TestSARIFSink_BlastRadiusBumpsSecuritySeverity(t *testing.T) {
	f := sample()
	if f.Result.ExtraData == nil {
		f.Result.ExtraData = map[string]string{}
	}
	f.Result.ExtraData["blast_radius"] = "true"
	f.Result.ExtraData["aws_privileged"] = "true"

	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")
	s.Emit(f)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	props := results[0].(map[string]any)["properties"].(map[string]any)
	if got := props["security-severity"]; got != "9.5" {
		t.Errorf("security-severity = %v, want 9.5 for blast_radius=true", got)
	}
	if got := props["blast_radius"]; got != "true" {
		t.Errorf("blast_radius prop missing or wrong: %v", got)
	}
}

func TestSARIFSink_NoBlastRadiusNoSecuritySeverity(t *testing.T) {
	f := sample() // sample() has no blast_radius flag
	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")
	s.Emit(f)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	props := results[0].(map[string]any)["properties"].(map[string]any)
	if _, ok := props["security-severity"]; ok {
		t.Errorf("security-severity must be absent without blast_radius (rule-level 9.0 applies)")
	}
}

func TestTableSinkColumns(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("table", &buf, "test")
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
			s, _ := NewSink("table", &buf, "test")
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
	s, _ := NewSink("table", &buf, "test")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("zero findings should produce no output, got %q", buf.String())
	}
}
