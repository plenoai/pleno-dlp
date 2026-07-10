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
