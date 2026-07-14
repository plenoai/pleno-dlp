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
		"path: ${{ runner.temp }}/homebrew-formula",
		"retention-days: 30",
		"Update Homebrew formula",
		"Gem::Version",
		"tap formula differs for existing version",
	} {
		if !strings.Contains(release, required) {
			t.Errorf("release.yml must contain %q", required)
		}
	}
	if strings.Contains(release, "gh release upload") {
		t.Error("release.yml must not attach assets after GoReleaser publishes")
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
