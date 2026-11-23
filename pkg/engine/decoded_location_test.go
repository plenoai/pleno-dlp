package engine

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Findings in decoded variants carry the path, line, RawSpan, and inline
// pragma of the encoded text that produced them (#964).
func TestDecodedFindingsResolveSourceLocation(t *testing.T) {
	secret := `apitoken = "oauth2value"`
	encodings := map[string]string{
		"base64":  base64.StdEncoding.EncodeToString([]byte(secret + " padding to a long run")),
		"percent": url.PathEscape(secret),
	}
	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			data := "first line\nsecond line\nblob: " + enc + "\nfourth line " + enc + " // pleno-dlp:allow\n"
			run := func(md sources.Metadata, st sources.SourceType) []Finding {
				sink := &engineRecordingSink{}
				eng := NewWithDetectors([]detectors.Detector{assignDet{}}, Options{Concurrency: 1, NoVerify: true}, sink)
				if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
					Data: []byte(data), SourceType: st, SourceMetadata: md,
				}}}); err != nil {
					t.Fatal(err)
				}
				var out []Finding
				for _, f := range sink.Findings() {
					if f.Result.ExtraData["decoded_from"] == name {
						out = append(out, f)
					}
				}
				return out
			}

			fs := run(sources.Metadata{Stdin: &sources.StdinMeta{Locations: map[int]sources.LineLocation{
				3: {Path: "fixture.txt", Line: 40},
				4: {Path: "fixture.txt", Line: 41},
			}}}, sources.SourceStdin)
			if len(fs) == 0 {
				t.Fatal("no decoded finding")
			}
			f := fs[0]
			fm := f.Chunk.SourceMetadata.Filesystem
			if fm == nil || fm.Path != "fixture.txt" || fm.Line != 40 {
				t.Fatalf("location = %+v, want fixture.txt:40", fm)
			}
			if f.RawSpan == nil || f.RawSpan[0] < len("first line\nsecond line\nblob: ") || f.RawSpan[1] > len(data) {
				t.Fatalf("RawSpan = %v, want span of the encoded run", f.RawSpan)
			}
			if f.InlineAllowed {
				t.Fatal("line 3 has no pragma but finding is inline-allowed")
			}

			fs = run(sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "fixture.txt", Line: 1}}, sources.SourceFilesystem)
			if len(fs) == 0 {
				t.Fatal("no decoded filesystem finding")
			}
			if got := fs[0].Chunk.SourceMetadata.Filesystem.Line; got != 3 {
				t.Fatalf("filesystem line = %d, want 3", got)
			}
		})
	}
}

// The pragma on the encoded line suppresses the decoded finding.
func TestDecodedFindingHonoursInlinePragma(t *testing.T) {
	enc := url.PathEscape(`apitoken = "oauth2value"`)
	data := "x\n" + enc + " # pleno-dlp:allow\n"
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{assignDet{}}, Options{Concurrency: 1, NoVerify: true}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(data), SourceType: sources.SourceStdin,
		SourceMetadata: sources.Metadata{Stdin: &sources.StdinMeta{Locations: map[int]sources.LineLocation{2: {Path: "a.php", Line: 9}}}},
	}}}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range sink.Findings() {
		if f.Result.ExtraData["decoded_from"] != "percent" {
			continue
		}
		found = true
		if !f.InlineAllowed {
			t.Fatalf("decoded finding on pragma line not inline-allowed: %+v", f.Chunk.SourceMetadata)
		}
		if fm := f.Chunk.SourceMetadata.Filesystem; fm == nil || fm.Path != "a.php" || fm.Line != 9 {
			t.Fatalf("location = %+v, want a.php:9", fm)
		}
	}
	if !found {
		t.Fatal("no decoded finding")
	}
}
