package all

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const modulePath = "github.com/plenoai/pleno-dlp/"

// TestContractRedactedIsCentralised verifies that every registered detector
// masks through the shared detectors.SafeResults/SafeRedacted contract and
// that its fixtures run through redactiontest, which fails whenever Redacted
// contains the complete Raw or RawV2. JSON, table and hook output only print
// Redacted, so a detector outside this contract could leak its secret.
func TestContractRedactedIsCentralised(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	for _, d := range detectors.All() {
		d := d
		t.Run(d.Type().String(), func(t *testing.T) {
			t.Parallel()
			typ := reflect.TypeOf(d)
			if typ.Kind() == reflect.Pointer {
				typ = typ.Elem()
			}
			pkg := typ.PkgPath()
			if !strings.HasPrefix(pkg, modulePath) {
				t.Fatalf("detector %T has unexpected package %q", d, pkg)
			}
			dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, modulePath)))
			src, tests := readPackage(t, dir)
			if !strings.Contains(src, "detectors.SafeResults(") && !strings.Contains(src, "detectors.SafeRedacted(") {
				t.Errorf("detector %T (%s) does not mask through detectors.SafeResults or SafeRedacted", d, pkg)
			}
			if !strings.Contains(tests, "redactiontest.") {
				t.Errorf("detector %T (%s) has no fixture checked by redactiontest", d, pkg)
			}
		})
	}
}

func readPackage(t *testing.T, dir string) (src, tests string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("read detector package %s: %v", dir, err)
	}
	var s, ts strings.Builder
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.HasSuffix(file, "_test.go") {
			ts.Write(body)
		} else {
			s.Write(body)
		}
	}
	return s.String(), ts.String()
}
