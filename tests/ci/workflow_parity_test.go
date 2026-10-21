package ci

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTestAndReleaseUseCentralFullRaceGate(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	sharedGates := []string{
		"sudo add-apt-repository -y ppa:git-core/ppa",
		"go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...",
		"go vet ./...",
		"select(.finding and .finding.osv != \"GO-2026-5932\")",
		"go build ./...",
		"bash tests/ci/full-race.sh",
		"go test ./pkg/connectors -run '^TestSourceFixtureDetectorKeywordMatrix$' -race -count=1",
		"bash tests/e2e/run.sh",
		"go test ./pkg/telemetry/crash -count=1",
		"node --test workers/crash-relay/crash-relay.test.js",
		"go test -tags=detector_unit ./pkg/detectors/... -race -count=1 -timeout 15m",
	}
	for _, name := range []string{"test.yml", "release.yml"} {
		data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Count(text, "bash tests/ci/full-race.sh") != 1 {
			t.Errorf("%s must invoke centralized race gate exactly once", name)
		}
		if strings.Contains(text, "go test ./... -race") {
			t.Errorf("%s contains a divergent inline full-race command", name)
		}
		for _, gate := range sharedGates {
			if !strings.Contains(text, gate) {
				t.Errorf("%s omits main's shared release gate %q", name, gate)
			}
		}
	}
}

func TestReleaseWorkflowRemainsTagOnlyAndProvisionsJobTools(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	releaseData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	release := string(releaseData)
	header := strings.SplitN(release, "jobs:", 2)[0]
	if !strings.Contains(header, "on:\n  push:\n    tags: ['v*']") || strings.Contains(header, "pull_request:") || strings.Contains(header, "workflow_dispatch:") {
		t.Error("release.yml must publish only from version tag pushes")
	}

	setupGoJobs := strings.Count(release, "- uses: actions/setup-go@")
	if setupGoJobs != 3 || strings.Count(release, "cache: false") != setupGoJobs || strings.Contains(release, "cache: true") {
		t.Errorf("all %d release Go setup jobs must disable cache to avoid flash disk pressure", setupGoJobs)
	}

	cmakeInstall := strings.Index(release, "Install native build configuration tool")
	cmakeVersion := strings.Index(release, "cmake --version")
	if cmakeInstall < 0 || cmakeVersion < cmakeInstall || !strings.Contains(release, "sudo apt-get install -y --no-install-recommends cmake") {
		t.Error("native release job must install CMake before checking or building with it")
	}

	rubySetup := strings.Index(release, "ruby/setup-ruby@824c0e29fdfc7d689c191c27acc969d2d04b7dd8 # v1.331.0")
	formulaValidation := strings.Index(release, "Validate Homebrew formula")
	if rubySetup < 0 || formulaValidation < rubySetup || !strings.Contains(release[rubySetup:formulaValidation], "ruby-version: '3.4'") {
		t.Error("Homebrew validation must provision pinned Ruby before invoking ruby")
	}
}

func TestReleaseDraftMeasuresCleanFlashCapacityBeforeSerialBuilds(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	releaseData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	release := string(releaseData)
	draftStart := strings.Index(release, "\n  draft:\n")
	if draftStart < 0 {
		t.Fatal("release.yml must define draft and finalize jobs")
	}
	finalizeStart := strings.Index(release[draftStart+1:], "\n  finalize:\n")
	if finalizeStart < 0 {
		t.Fatal("release.yml must define draft and finalize jobs")
	}
	draft := release[draftStart+1 : draftStart+1+finalizeStart]
	for _, required := range []string{
		"runs-on: [self-hosted, linux, arm64, hikae-flash]",
		"timeout-minutes: 30",
		"go clean -cache",
		`df -Pk "$GITHUB_WORKSPACE" /tmp`,
		"go env GOCACHE GOMODCACHE",
		`tee "$RUNNER_TEMP/disk-before-goreleaser.txt"`,
		"uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2",
		"name: release-draft-disk-before-goreleaser",
		"path: ${{ runner.temp }}/disk-before-goreleaser.txt",
		"if-no-files-found: error",
		"retention-days: 1",
		"args: release --clean --parallelism=1",
	} {
		if !strings.Contains(draft, required) {
			t.Errorf("release draft job must contain %q", required)
		}
	}
	staging := strings.Index(draft, "name: Validate native release inputs")
	capacity := strings.Index(draft, "name: Record clean Go build capacity")
	evidence := strings.Index(draft, "name: Preserve Go build capacity evidence")
	build := strings.Index(draft, "args: release --clean --parallelism=1")
	if staging < 0 || capacity < staging || evidence < capacity || build < evidence {
		t.Error("draft must stage native inputs, record capacity, preserve the evidence, then build")
	}
}

func TestReleasePublishesNativeAssetsInsideImmutableBoundary(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "release-native.yml")); !os.IsNotExist(err) {
		t.Fatalf("release-native.yml must not publish after the immutable release: %v", err)
	}

	releaseData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	release := string(releaseData)
	for _, required := range []string{
		"group: ${{ github.workflow }}-release",
		"queue: max",
		"needs: [quality, native]",
		"needs: draft",
		"actions/upload-artifact@",
		"actions/download-artifact@",
		"path: ${{ runner.temp }}/native-release",
		"Validate native release inputs",
		"install -m 0644",
		"Publish immutable release",
		"--field draft=false",
		"false:true) echo \"release is already immutable\"",
		"true:false)",
		"needs: finalize",
		"path: dist/homebrew/Casks/pleno-dlp.rb",
		"path: ${{ runner.temp }}/homebrew-formula",
		"path=Casks/pleno-dlp.rb",
		"releases/download/v#{version}/pleno-dlp_${platform}.tar.gz",
		"retention-days: 30",
		"Update Homebrew formula",
		"Gem::Version",
		"tap formula differs for existing version",
		"error_file=$(mktemp)",
		"sha_args=()",
		"sha_args=(--raw-field sha=\"$sha\")",
		"grep -Fq \"HTTP 404\"",
		"\"${sha_args[@]}\"",
		"update_response=$(gh api --method PUT",
		"updated_ref=$(jq -er",
		"contents/$path?ref=$updated_ref",
		"for attempt in 1 2 3 4 5",
	} {
		if !strings.Contains(release, required) {
			t.Errorf("release.yml must contain %q", required)
		}
	}
	if strings.Contains(release, "gh release upload") {
		t.Error("release.yml must not attach assets after GoReleaser publishes")
	}
	if strings.Contains(release, "homebrew/Formula/") || strings.Contains(release, "path=Formula/") {
		t.Error("release.yml must use the Homebrew cask paths emitted by homebrew_casks")
	}
	if strings.Contains(release, "releases/download/$TAG/pleno-dlp_${platform}.tar.gz") {
		t.Error("release.yml must validate the version interpolation emitted by homebrew_casks")
	}
	if strings.Count(release, "contents: write") != 2 {
		t.Error("only the draft and finalize jobs may write release contents")
	}
	validation := strings.Index(release, "Validate native release inputs")
	staging := strings.Index(release, "install -m 0644")
	attestation := strings.LastIndex(release, "actions/attest-build-provenance@")
	publication := strings.Index(release, "Publish immutable release")
	if validation < 0 || staging < validation {
		t.Error("native files must be validated before workspace staging")
	}
	if attestation < 0 || publication < attestation {
		t.Error("immutable publication must follow every provenance attestation")
	}
	homebrew := strings.Index(release, "Update Homebrew formula")
	if homebrew < publication {
		t.Error("Homebrew may only update after immutable publication")
	}

	configData, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config := string(configData)
	for _, glob := range []string{
		"./dist-native/*.tar.gz",
		"./dist-native/*.tar.gz.sha256",
		"./dist-native/*.tar.gz.sigstore.json",
		"./dist-native/*.tar.gz.spdx.json",
	} {
		if !strings.Contains(config, glob) {
			t.Errorf("GoReleaser must publish native artifact glob %q", glob)
		}
	}
	if !strings.Contains(config, "draft: true") || !strings.Contains(config, "replace_existing_draft: true") {
		t.Error("GoReleaser must leave a replaceable draft for the final publication step")
	}
	if !strings.Contains(config, "skip_upload: true") {
		t.Error("GoReleaser must defer Homebrew publication until the release is immutable")
	}
}
