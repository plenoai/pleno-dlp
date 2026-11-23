package engine

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/mongodb"
	"github.com/plenoai/pleno-dlp/pkg/detectors/mysql"
	"github.com/plenoai/pleno-dlp/pkg/detectors/postgres"
	"github.com/plenoai/pleno-dlp/pkg/detectors/redis"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestURIFindingsAttributeToURILine pins #920: URI detectors report the
// short password as Raw, and the same bytes occur earlier in the
// staged diff (inside a go.sum hash). Each finding must resolve to its
// URI's file and line, not to the first occurrence of the password.
func TestURIFindingsAttributeToURILine(t *testing.T) {
	data := "golang.org/x/net v0.1.0 h1:V1m40wESHTgc1422pwwBSKYuIZq8vL2xQ=\n" + // 1: go.sum, contains "pw" and "Zq8vL2"
		"package conf\n" + // 2
		"var pg = \"postgres://app:pw@db.internal:5432/app\"\n" + // 3 // pleno-dlp:allow
		"var my = \"mysql://app:pw@mysql.internal:3306/app\"\n" + // 4 // pleno-dlp:allow
		"var mg = \"mongodb://app:Zq8vL2@mongo.internal:27017/app\"\n" + // 5 // pleno-dlp:allow
		"var rd = \"redis://app:pw@redis.internal:6379/0\"\n" // 6 // pleno-dlp:allow
	locs := map[int]sources.LineLocation{
		1: {Path: "go.sum", Line: 170},
		2: {Path: "conf.go", Line: 1},
		3: {Path: "conf.go", Line: 2},
		4: {Path: "conf.go", Line: 3},
		5: {Path: "conf.go", Line: 4},
		6: {Path: "conf.go", Line: 5},
	}
	sink := &engineRecordingSink{}
	dets := []detectors.Detector{postgres.Scanner{}, mysql.Scanner{}, mongodb.Scanner{}, redis.Scanner{}}
	eng := NewWithDetectors(dets, Options{Concurrency: 1, NoVerify: true}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(data), SourceType: sources.SourceStdin,
		SourceMetadata: sources.Metadata{Stdin: &sources.StdinMeta{Locations: locs}},
	}}}); err != nil {
		t.Fatal(err)
	}
	want := map[detectors.DetectorType]int{detectors.Postgres: 2, detectors.MySQL: 3, detectors.MongoDB: 4, detectors.Redis: 5}
	got := map[detectors.DetectorType]bool{}
	for _, f := range sink.Findings() {
		line, ok := want[f.Result.DetectorType]
		if !ok {
			continue
		}
		got[f.Result.DetectorType] = true
		if fm := f.Chunk.SourceMetadata.Filesystem; fm == nil || fm.Path != "conf.go" || fm.Line != line {
			t.Errorf("%v at %+v, want conf.go:%d", f.Result.DetectorType, fm, line)
		}
	}
	for typ := range want {
		if !got[typ] {
			t.Errorf("%v: no finding", typ)
		}
	}
}

// The filesystem variant of #920: a MySQL URI sharing its password with
// an earlier Postgres URI resolves to its own line.
func TestURIFindingsSharedPasswordFilesystemLine(t *testing.T) {
	data := "a = \"postgres://app:pw@db.internal:5432/app\"\n" + // pleno-dlp:allow
		"b = 1\n" +
		"c = \"mysql://app:pw@mysql.internal:3306/app\"\n" // pleno-dlp:allow
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{postgres.Scanner{}, mysql.Scanner{}}, Options{Concurrency: 1, NoVerify: true}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte(data), SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "conf.py", Line: 1}},
	}}}); err != nil {
		t.Fatal(err)
	}
	want := map[detectors.DetectorType]int{detectors.Postgres: 1, detectors.MySQL: 3}
	for _, f := range sink.Findings() {
		if line, ok := want[f.Result.DetectorType]; ok {
			if got := f.Chunk.SourceMetadata.Filesystem.Line; got != line {
				t.Errorf("%v line = %d, want %d", f.Result.DetectorType, got, line)
			}
			delete(want, f.Result.DetectorType)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing findings: %v", want)
	}
}
