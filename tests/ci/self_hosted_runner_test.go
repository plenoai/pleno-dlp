package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Runner labels are pinned because this repository has measured capacity
// exceptions and does not use GitHub-hosted runners.
const hikaeFlashLabels = "[self-hosted, linux, arm64, hikae-flash]"
const hikaeLongLabels = "[self-hosted, linux, arm64, hikae-long]"

var (
	runnerLine = regexp.MustCompile(`^(\s*)runs-on:\s*(.*)$`)
	jobLine    = regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):\s*$`)
	hostedOS   = regexp.MustCompile(`ubuntu|macos|windows`)
)

func TestWorkflowsUsePinnedRunnerPolicy(t *testing.T) {
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
			if strings.Contains(value, "${{") {
				t.Errorf("%s:%d: matrix-selected runner %q is not validated", name, i+1, value)
				continue
			}
			found = true
			if hostedOS.MatchString(value) {
				t.Errorf("%s:%d: runs-on must not select a GitHub-hosted runner: %q", name, i+1, value)
			}
			if !runnerMatchesPolicy(name, job, value) {
				t.Errorf("%s:%d: runs-on = %q, want %q", name, i+1, value, expectedRunnerLabels(name, job))
			}
		}
	}
	if !found {
		t.Fatal("no pinned runs-on jobs found; runner policy test is ineffective")
	}
}

func expectedRunnerLabels(workflow, job string) string {
	if workflow == "test.yml" && job == "test" ||
		workflow == "release.yml" && (job == "quality" || job == "native") {
		return hikaeLongLabels
	}
	return hikaeFlashLabels
}

func runnerMatchesPolicy(workflow, job, value string) bool {
	return !strings.Contains(value, "${{") && value == expectedRunnerLabels(workflow, job)
}

func TestRunnerPolicyRejectsUnvalidatedMatrixExpressions(t *testing.T) {
	for _, value := range []string{"${{ matrix.runner }}", "${{ fromJSON(matrix.runner) }}"} {
		if runnerMatchesPolicy("release.yml", "native", value) {
			t.Errorf("matrix expression %q bypasses the pinned runner policy", value)
		}
	}
}
