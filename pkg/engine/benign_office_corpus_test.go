package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// TestBenignOfficeCorpusHasNoFindings guards against structural false
// positives from OLE2 extraction: binary record bytes, UTF-16 decodes of
// raw streams, property-set headers, or embedded-object wrappers turning
// into detector matches. The corpus (testdata/benign-office) holds no
// credentials, so every finding is noise.
func TestBenignOfficeCorpusHasNoFindings(t *testing.T) {
	files, err := filepath.Glob("testdata/benign-office/*.*")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, f := range files {
		if filepath.Ext(f) == ".md" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		results, err := engine.ScanBytes(context.Background(), data, engine.Options{})
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, r := range results {
			t.Errorf("%s: unexpected finding %s %q", filepath.Base(f), r.DetectorType, r.Redacted)
		}
	}
	if scanned < 6 {
		t.Fatalf("corpus incomplete: %d files", scanned)
	}
}
