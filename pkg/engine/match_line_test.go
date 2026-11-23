package engine

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// assignDet reports the value of `token = "<v>"`, returning Raw only; the
// engine must attribute it to the assignment line, not to an earlier
// unrelated occurrence of the same literal (#874).
type assignDet struct{}

var assignRe = regexp.MustCompile(`apitoken = "([a-z0-9]+)"`)

func (assignDet) Type() detectors.DetectorType { return detectors.AWS }
func (assignDet) Keywords() []string           { return []string{"apitoken"} }
func (assignDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var out []detectors.Result
	for _, m := range assignRe.FindAllSubmatch(data, -1) {
		out = append(out, detectors.Result{DetectorType: detectors.AWS, Raw: m[1]})
	}
	return out, nil
}

func TestFindingLineUsesDetectorWindowNotEarliestOccurrence(t *testing.T) {
	var b strings.Builder
	b.WriteString("// mentions oauth2value in a doc comment\n")
	for i := 0; i < 200; i++ { // push the assignment beyond vicinityRadius
		b.WriteString("// filler line padding padding padding\n")
	}
	b.WriteString("apitoken = \"oauth2value\"\n") // line 202
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{assignDet{}}, Options{Concurrency: 1, NoVerify: true}, sink)
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(b.String()), SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "a.go", Line: 1}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	fs := sink.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if got := fs[0].Chunk.SourceMetadata.Filesystem.Line; got != 202 {
		t.Fatalf("line = %d, want 202", got)
	}
	if fs[0].RawSpan == nil || string(b.String()[fs[0].RawSpan[0]:fs[0].RawSpan[1]]) != "oauth2value" {
		t.Fatalf("RawSpan = %v, want span of the assigned value", fs[0].RawSpan)
	}
}

// A diff-backed chunk must not fan a result out to occurrences of the same
// bytes outside the detector's window (#874): only the matched assignment
// is reported, not the unrelated doc-comment line.
func TestDiffLocationsLimitedToDetectorWindow(t *testing.T) {
	var b strings.Builder
	b.WriteString("// mentions oauth2value in a doc comment\n")
	for i := 0; i < 200; i++ {
		b.WriteString("// filler line padding padding padding\n")
	}
	b.WriteString("apitoken = \"oauth2value\"\n")
	locs := map[int]sources.LineLocation{
		1:   {Path: "doc.go", Line: 5},
		202: {Path: "conf.go", Line: 157},
	}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{assignDet{}}, Options{Concurrency: 1, NoVerify: true}, sink)
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(b.String()), SourceType: sources.SourceStdin,
		SourceMetadata: sources.Metadata{Stdin: &sources.StdinMeta{Locations: locs}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	fs := sink.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if fm := fs[0].Chunk.SourceMetadata.Filesystem; fm == nil || fm.Path != "conf.go" || fm.Line != 157 {
		t.Fatalf("location = %+v, want conf.go:157", fm)
	}
}

// Within one window the occurrence the detector confirms on its own line
// wins over an earlier unrelated mention (#874).
func TestFindingLinePrefersConfirmedOccurrenceInWindow(t *testing.T) {
	data := "// oauth2value is documented here\napitoken = \"oauth2value\"\n"
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{assignDet{}}, Options{Concurrency: 1, NoVerify: true}, sink)
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(data), SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "a.go", Line: 1}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	fs := sink.Findings()
	if len(fs) != 1 || fs[0].Chunk.SourceMetadata.Filesystem.Line != 2 {
		t.Fatalf("findings = %+v, want one at line 2", fs)
	}
}
