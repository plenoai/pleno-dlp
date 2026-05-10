// Sync test: rejects drift between docs/verify-coverage.md (the human
// source of truth) and Classes (the Go map the CLI consumes). If either
// file is edited without the other, this test fails with a precise diff.
//
// The sibling test pkg/detectors/verifycoverage_test.go covers the
// other half: drift between the doc and the live registry.
package verifycoverage_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/verifycoverage"
)

func TestClassesMatchesCoverageDoc(t *testing.T) {
	docClasses, err := loadDocMachineBlock(t)
	if err != nil {
		t.Fatalf("load doc machine block: %v", err)
	}

	for name, docClass := range docClasses {
		got, ok := verifycoverage.Classes[name]
		if !ok {
			t.Errorf("doc lists DetectorType=%q (class=%s) but it is missing from verifycoverage.Classes", name, docClass)
			continue
		}
		if string(got) != docClass {
			t.Errorf("DetectorType=%q: doc class=%s, Classes class=%s", name, docClass, got)
		}
	}

	for name, gotClass := range verifycoverage.Classes {
		if _, ok := docClasses[name]; !ok {
			t.Errorf("verifycoverage.Classes lists DetectorType=%q (class=%s) but it is missing from docs/verify-coverage.md machine block", name, gotClass)
		}
	}
}

func loadDocMachineBlock(t *testing.T) (map[string]string, error) {
	t.Helper()
	path := findCoverageDoc(t)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	const fence = "```coverage-machine"
	out := map[string]string{}
	in := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case !in && strings.HasPrefix(line, fence):
			in = true
		case in && strings.HasPrefix(line, "```"):
			in = false
		case in && strings.HasPrefix(line, "type="):
			name, class := parseTypeClass(line)
			if name != "" {
				out[name] = class
			}
		}
	}
	return out, scanner.Err()
}

func parseTypeClass(line string) (name, class string) {
	for p := range strings.FieldsSeq(line) {
		switch {
		case strings.HasPrefix(p, "type="):
			name = strings.TrimPrefix(p, "type=")
		case strings.HasPrefix(p, "class="):
			class = strings.TrimPrefix(p, "class=")
		}
	}
	return name, class
}

func findCoverageDoc(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		candidate := filepath.Join(dir, "docs", "verify-coverage.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("docs/verify-coverage.md not found from %s", dir)
	return ""
}
