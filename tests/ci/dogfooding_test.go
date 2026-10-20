package ci

import (
	"io/fs"
	"os"
	"path/filepath"
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

// TestDogfoodingInstallsReleasedBinaryFromHomebrewTap pins the decision
// recorded in docs/dogfooding.md: operator machines run the signed release
// binary from the Homebrew tap, kept current by the release pipeline, rather
// than an ad-hoc mise go: build.
func TestDogfoodingInstallsReleasedBinaryFromHomebrewTap(t *testing.T) {
	root := dogfoodRoot(t)

	doc, err := os.ReadFile(filepath.Join(root, "docs", "dogfooding.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"brew install plenoai/tap/pleno-dlp",
		"brew upgrade pleno-dlp",
		"plenoai/homebrew-tap",
	} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("docs/dogfooding.md must document %q", want)
		}
	}

	config, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"homebrew_casks:",
		"name: homebrew-tap",
		"owner: plenoai",
		"skip_upload: true",
	} {
		if !strings.Contains(string(config), want) {
			t.Errorf(".goreleaser.yaml must keep publishing the Homebrew cask: missing %q", want)
		}
	}

	release, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rel := string(release)
	homebrew := strings.Index(rel, "homebrew:")
	if homebrew < 0 {
		t.Fatal("release.yml must keep the homebrew job that updates the tap")
	}
	if !strings.Contains(rel[homebrew:], "needs: finalize") {
		t.Error("the Homebrew tap update must run only after the release is finalized")
	}
	if !strings.Contains(rel, "path=Casks/pleno-dlp.rb") {
		t.Error("the Homebrew tap update must target Casks/pleno-dlp.rb")
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
			t.Errorf("reintroduced an ad-hoc mise pin in %s; dogfood via the Homebrew tap (docs/dogfooding.md)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
