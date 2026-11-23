package ci

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// dogfoodRoot resolves the repository root from this test file.
func dogfoodRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestDogfoodingInstallsReleasedBinaryThroughAqua pins the decision recorded
// in docs/dogfooding.md: operator machines run the signed release binary
// through aqua, which verifies the cosign-signed checksums.txt and the GitHub
// artifact attestation, rather than an ad-hoc mise go: build or a Homebrew tap.
func TestDogfoodingInstallsReleasedBinaryThroughAqua(t *testing.T) {
	root := dogfoodRoot(t)
	read := func(rel ...string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(append([]string{root}, rel...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	doc := read("docs", "dogfooding.md")
	for _, want := range []string{"aqua -c aqua/aqua.yaml i", "aqua/registry.yaml", "aquaproj/aqua-registry"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/dogfooding.md must document %q", want)
		}
	}

	aquaConfig := read("aqua", "aqua.yaml")
	pin := regexp.MustCompile(`(?m)^\s+- name: plenoai/pleno-dlp@(v\d+\.\d+\.\d+)$`).FindStringSubmatch(aquaConfig)
	if pin == nil {
		t.Fatal("aqua/aqua.yaml must pin plenoai/pleno-dlp to a released vX.Y.Z")
	}
	if !strings.Contains(aquaConfig, "require_checksum: true") {
		t.Error("aqua/aqua.yaml must require checksums")
	}
	checksums := read("aqua", "aqua-checksums.json")
	if !strings.Contains(checksums, "github.com/plenoai/pleno-dlp/"+pin[1]+"/pleno-dlp_darwin_arm64.tar.gz") {
		t.Errorf("aqua/aqua-checksums.json must record %s; run aqua -c aqua/aqua.yaml upc -prune", pin[1])
	}

	registry := read("aqua", "registry.yaml")
	latest := registry[strings.LastIndex(registry, `version_constraint: "true"`):]
	for _, want := range []string{
		"asset: pleno-dlp_{{.OS}}_{{.Arch}}.{{.Format}}",
		"asset: checksums.txt",
		"asset: checksums.txt.sigstore.json",
		`^https://github\\.com/plenoai/pleno-dlp/\\.github/workflows/release\\.yml@refs/tags/\\Q{{.Version}}\\E$`,
		"signer_workflow: plenoai/pleno-dlp/.github/workflows/release.yml",
	} {
		if !strings.Contains(latest, want) {
			t.Errorf("aqua/registry.yaml current override must contain %q", want)
		}
	}

	// The registry entry depends on these release asset names and signatures.
	config := read(".goreleaser.yaml")
	for _, want := range []string{
		`name_template: "{{.ProjectName}}_{{.Os}}_{{.Arch}}"`,
		"name_template: 'checksums.txt'",
		"artifacts: checksum",
		`signature: "${artifact}.sigstore.json"`,
	} {
		if !strings.Contains(config, want) {
			t.Errorf(".goreleaser.yaml must keep the asset contract aqua relies on: missing %q", want)
		}
	}
	release := read(".github", "workflows", "release.yml")
	if !strings.Contains(release, "actions/attest-build-provenance@") || !strings.Contains(release, "dist/*.tar.gz") {
		t.Error("release.yml must attest the archives aqua verifies")
	}

	for name, text := range map[string]string{".goreleaser.yaml": config, "release.yml": release} {
		lower := strings.ToLower(text)
		for _, banned := range []string{"homebrew", "brew_"} {
			if strings.Contains(lower, banned) {
				t.Errorf("%s must not publish to Homebrew (retired; see docs/dogfooding.md): found %q", name, banned)
			}
		}
	}
}

// TestNoAdHocMisePinForPlenoDLP rejects reintroducing the drifted build
// entry documented in docs/dogfooding.md. The needle is assembled at runtime
// so this test file does not match itself.
func TestNoAdHocMisePinForPlenoDLP(t *testing.T) {
	root := dogfoodRoot(t)
	pin := "go:github.com/" + "plenoai/pleno-dlp/cmd/pleno-dlp"

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "docs", ".claude", "website":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".md") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), pin) {
			t.Errorf("reintroduced an ad-hoc mise pin in %s; dogfood via aqua (docs/dogfooding.md)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
