package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// hikaeFlashLabels is the AWS Lambda MicroVM self-hosted runner label set that
// jobs without a measured capacity exception must target. GitHub-hosted runners (ubuntu-latest,
// macos-*, windows-*) are retired for this repository.
const hikaeFlashLabels = "[self-hosted, linux, arm64, hikae-flash]"

var (
	runnerLine = regexp.MustCompile(`^(\s*)runs-on:\s*(.*)$`)
	jobLine    = regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):\s*$`)
	hostedOS   = regexp.MustCompile(`ubuntu|macos|windows`)
)

func TestWorkflowsUseSelfHostedFlashRunner(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	dir := filepath.Join(root, ".github", "workflows")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		job := ""
		for i, line := range strings.Split(string(data), "\n") {
			if match := jobLine.FindStringSubmatch(line); match != nil {
				job = match[1]
			}
			match := runnerLine.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			value := strings.TrimSpace(match[2])
			// A matrix-selected runner is validated by its include entries;
			// the labels themselves are not pinned in this line.
			if strings.HasPrefix(value, "${{") {
				continue
			}
			found = true
			if hostedOS.MatchString(value) {
				t.Errorf("%s:%d: runs-on must not select a GitHub-hosted runner: %q", name, i+1, value)
			}
			want := hikaeFlashLabels
			// Measured ENOSPC: HikaruEgashira/iac-aws#697.
			if name == "test.yml" && (job == "test" || job == "opf-native") {
				want = "[self-hosted, linux, arm64, hikae-long]"
			}
			if value != want {
				t.Errorf("%s:%d: runs-on = %q, want %q", name, i+1, value, want)
			}
		}
	}
	if !found {
		t.Fatal("no pinned runs-on jobs found; runner policy test is ineffective")
	}
}
