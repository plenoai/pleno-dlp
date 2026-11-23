package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestInlineAllowedAt(t *testing.T) {
	const secret = "SECRETVALUE"
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"same line", "a\nkey=SECRETVALUE # pleno-dlp:allow\nb\n", true},
		{"next-line pragma", "# pleno-dlp:allow-next-line\nkey=SECRETVALUE\n", true},
		{"next-line pragma at start of data", "// pleno-dlp:allow-next-line\nSECRETVALUE", true},
		{"plain allow on previous line does not apply", "# pleno-dlp:allow\nkey=SECRETVALUE\n", false},
		{"next-line pragma two lines up", "# pleno-dlp:allow-next-line\n\nkey=SECRETVALUE\n", false},
		{"pragma on following line", "key=SECRETVALUE\n# pleno-dlp:allow\n", false},
		{"kingfisher compat", "key=SECRETVALUE # kingfisher:ignore\n", true},
		{"gitleaks compat", "key=SECRETVALUE # gitleaks:allow\n", true},
		{"no pragma", "key=SECRETVALUE\n", false},
		{"pragma on another secret line", "x=SECRETVALUE\ny=OTHER # pleno-dlp:allow\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inlineAllowedIn([]byte(tc.data), []byte(secret)); got != tc.want {
				t.Fatalf("inlineAllowedIn(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
	multi := []byte("-----BEGIN\nAAAA\nBBBB\n-----END # pleno-dlp:allow\n")
	if !inlineAllowedAt(multi, 0, bytes.Index(multi, []byte(" #"))) {
		t.Fatal("pragma on the closing line of a multi-line secret must apply")
	}
	if inlineAllowedAt([]byte("abc"), 2, 1) || inlineAllowedAt([]byte("abc"), 0, 9) {
		t.Fatal("out-of-range spans must not panic or match")
	}
}

func TestFingerprintStableAcrossLineAndVerification(t *testing.T) {
	mk := func(path string, line int, verified bool, raw string) Finding {
		return Finding{
			Detector: detectors.AWS,
			Result:   detectors.Result{Raw: []byte(raw), Verified: verified},
			Chunk: &sources.Chunk{SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{Path: path, Line: line},
			}},
		}
	}
	base := Fingerprint(mk("dir/a.env", 1, false, "AKIAX"))
	if len(base) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(base))
	}
	if got := Fingerprint(mk("./dir/a.env", 40, true, "AKIAX")); got != base {
		t.Fatalf("line, verification, and ./ prefix must not change the fingerprint")
	}
	if Fingerprint(mk("dir/b.env", 1, false, "AKIAX")) == base {
		t.Fatal("same secret in another file must get a distinct fingerprint")
	}
	if Fingerprint(mk("dir/a.env", 1, false, "AKIAY")) == base {
		t.Fatal("different secret must get a distinct fingerprint")
	}
	if strings.Contains(base, "AKIAX") {
		t.Fatal("fingerprint must not embed the secret")
	}
}

func TestFingerprintPathRelativeToWorkdir(t *testing.T) {
	wd := filepath.FromSlash("/repo/root")
	if got := normalizeFingerprintPath(filepath.Join(wd, "a", "b.env"), wd); got != "a/b.env" {
		t.Fatalf("got %q, want a/b.env", got)
	}
	outside := filepath.FromSlash("/elsewhere/b.env")
	if got := normalizeFingerprintPath(outside, wd); got != filepath.ToSlash(outside) {
		t.Fatalf("paths outside the workdir must stay absolute; got %q", got)
	}
	if got := normalizeFingerprintPath(filepath.FromSlash("/repo/rootish/x"), wd); strings.HasPrefix(got, "..") || got == "ish/x" {
		t.Fatalf("sibling prefix must not be treated as inside; got %q", got)
	}
}

func TestAllowlistMatchReasonPrecedence(t *testing.T) {
	f := Finding{
		Detector:      detectors.AWS,
		Result:        detectors.Result{Raw: []byte("AKIAEXAMPLEWORD")},
		Chunk:         &sources.Chunk{SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "x.env"}}},
		InlineAllowed: true,
	}
	a := &Allowlist{}
	if a.MatchReason(f) != "" {
		t.Fatal("inline pragma must be ignored unless HonorInline")
	}
	a.HonorInline = true
	if got := a.MatchReason(f); got != SuppressedByInline {
		t.Fatalf("got %q, want inline", got)
	}
	f.InlineAllowed = false
	a.AddFingerprints(Fingerprint(f))
	if got := a.MatchReason(f); got != SuppressedByBaseline {
		t.Fatalf("got %q, want baseline", got)
	}
	b := &Allowlist{}
	if err := b.Add(AllowlistEntry{RawContains: "exampleword"}); err != nil {
		t.Fatal(err)
	}
	if got := b.MatchReason(f); got != SuppressedByAllowlist {
		t.Fatalf("raw_contains must match case-insensitively; got %q", got)
	}
	c := &Allowlist{}
	if err := c.Add(AllowlistEntry{Fingerprint: Fingerprint(f), Detector: "OpenAI"}); err != nil {
		t.Fatal(err)
	}
	if c.Match(f) {
		t.Fatal("fingerprint entry with a mismatching detector must not match")
	}
	if err := c.Add(AllowlistEntry{}); err == nil {
		t.Fatal("empty entry must be rejected")
	}
}

func TestAllowlistSinkAuditsWithReason(t *testing.T) {
	a := &Allowlist{HonorInline: true}
	kept, audit := &captureSink{}, &captureSink{}
	s := NewAllowlistWithAudit(a, kept, audit)
	s.Emit(Finding{InlineAllowed: true, Result: detectors.Result{Raw: []byte("x")}})
	s.Emit(Finding{Result: detectors.Result{Raw: []byte("y")}})
	if len(kept.findings) != 1 || len(audit.findings) != 1 {
		t.Fatalf("kept=%d audit=%d, want 1/1", len(kept.findings), len(audit.findings))
	}
	if audit.findings[0].SuppressedBy != SuppressedByInline {
		t.Fatalf("SuppressedBy = %q", audit.findings[0].SuppressedBy)
	}
	if got := SuppressedByReason(s)[SuppressedByInline]; got != 1 {
		t.Fatalf("per-reason count = %d", got)
	}
}

func TestBaselineMergeAndRoundTrip(t *testing.T) {
	old := &Baseline{Version: BaselineVersion, Findings: []BaselineEntry{{Fingerprint: "a"}, {Fingerprint: "b"}}}
	merged, added, removed := old.Merge([]BaselineEntry{{Fingerprint: "b"}, {Fingerprint: "c"}, {Fingerprint: "c"}}, true)
	if added != 1 || removed != 1 || len(merged.Findings) != 2 {
		t.Fatalf("prune merge: added=%d removed=%d n=%d", added, removed, len(merged.Findings))
	}
	kept, _, removed := old.Merge([]BaselineEntry{{Fingerprint: "c"}}, false)
	if removed != 0 || len(kept.Findings) != 3 {
		t.Fatalf("no-prune merge must retain entries; n=%d", len(kept.Findings))
	}
	path := filepath.Join(t.TempDir(), "b.json")
	if err := WriteBaselineFile(path, kept); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaselineFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Fingerprints(), ",") != "a,b,c" {
		t.Fatalf("round trip = %v", got.Fingerprints())
	}
	if _, err := LoadBaseline(strings.NewReader(`{"version":2,"findings":[]}`)); err == nil {
		t.Fatal("unknown version must be rejected")
	}
	if _, err := LoadBaseline(strings.NewReader(`{"version":1,"findings":[{"detector":"AWS"}]}`)); err == nil {
		t.Fatal("entry without fingerprint must be rejected")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("atomic write must not leave temp files: %v", entries)
	}
}

// TestEngineMarksInlineAllowed exercises the real engine path: a buffered
// filesystem chunk with a same-line pragma is emitted with InlineAllowed.
func TestEngineMarksInlineAllowed(t *testing.T) {
	// Split literals keep the repository's own pre-commit scan quiet.
	data := []byte("a=AKIA" + "IOSFODNN7REALKEY # pleno-dlp:allow\nb=AKIA" + "IOSFODNN7OTHERKY\n")
	dets := []detectors.Detector{inlineFixtureDetector{}}
	sink := &captureSink{}
	eng := NewWithDetectors(dets, Options{NoVerify: true}, sink)
	src := &bytesSource{chunk: &sources.Chunk{
		SourceType:     sources.SourceFilesystem,
		Data:           data,
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "f.env", Line: 1}},
	}}
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range sink.findings {
		got[string(f.Result.Raw)] = f.InlineAllowed
	}
	if !got["AKIA"+"IOSFODNN7REALKEY"] || got["AKIA"+"IOSFODNN7OTHERKY"] {
		t.Fatalf("InlineAllowed by raw = %v", got)
	}
}

type inlineFixtureDetector struct{}

func (inlineFixtureDetector) Keywords() []string           { return []string{"AKIA"} }
func (inlineFixtureDetector) Type() detectors.DetectorType { return detectors.AWS }
func (inlineFixtureDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var out []detectors.Result
	for _, line := range bytes.Split(data, []byte("\n")) {
		if i := bytes.Index(line, []byte("AKIA")); i >= 0 && len(line) >= i+20 {
			out = append(out, detectors.Result{DetectorType: detectors.AWS, Raw: append([]byte(nil), line[i:i+20]...)})
		}
	}
	return out, nil
}
