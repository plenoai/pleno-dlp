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
// exceptions and does not use GitHub-hosted runners. plenoai runs on Blacksmith;
// the disk-heavy jobs use the 4 vCPU size.
const smallRunnerLabel = "blacksmith-2vcpu-ubuntu-2404-arm"
const largeRunnerLabel = "blacksmith-4vcpu-ubuntu-2404-arm"

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
			if !strings.HasPrefix(value, "blacksmith-") && hostedOS.MatchString(value) && !(name == "release.yml" && githubHostedRunners[job] == value) {
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

// githubHostedRunners are the only GitHub-hosted exceptions (ADR 0001):
//   - bindings-smoke-windows-*: cross-linked Windows bindings must load on
//     Windows before publishing (#879); Blacksmith has no Windows pool and wine
//     cannot run x86-64 PE images on the arm64 pool. No secrets or OIDC token.
//   - npm: npm rejects provenance bundles built on self-hosted runners
//     ("Only github-hosted runners are supported when publishing with
//     provenance", v0.71.4), so the staged npm publish runs GitHub-hosted.
var githubHostedRunners = map[string]string{
	"bindings-smoke-windows-amd64": "windows-2025",
	"bindings-smoke-windows-arm64": "windows-11-arm",
	"npm":                          "ubuntu-24.04-arm",
}

func expectedRunnerLabels(workflow, job string) string {
	if workflow == "release.yml" {
		if label, ok := githubHostedRunners[job]; ok {
			return label
		}
	}
	if workflow == "test.yml" && job == "test" ||
		workflow == "release.yml" && (job == "quality" || job == "native") {
		return largeRunnerLabel
	}
	return smallRunnerLabel
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

func TestWindowsSmokeGatesPublishing(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, job := range []string{"pypi", "npm"} {
		i := strings.Index(s, "\n  "+job+":\n")
		if i < 0 {
			t.Fatalf("release.yml has no %s job", job)
		}
		needs := s[i : i+strings.Index(s[i:], "\n    runs-on:")]
		for smoke := range githubHostedRunners {
			if !strings.HasPrefix(smoke, "bindings-smoke-windows-") {
				continue
			}
			if !strings.Contains(needs, smoke) {
				t.Errorf("%s must need %s so an unloadable Windows library never publishes", job, smoke)
			}
		}
	}
}
