package crash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetEnabledPreservesRelayEndpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, configFile)
	initial := fileConfig{
		Endpoint:         "https://crash.example.com/v1/pleno-dlp",
		FeedbackEndpoint: "https://feedback.example.com/v1/pleno-dlp",
	}
	b, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(key string) string {
		if key == EnvDir {
			return dir
		}
		return ""
	}
	for _, enabled := range []bool{true, false} {
		if _, err := SetEnabled(getenv, enabled); err != nil {
			t.Fatal(err)
		}
		got, found, err := readFile(dir)
		if err != nil || !found {
			t.Fatalf("read configuration: found=%v err=%v", found, err)
		}
		if got.CrashReports != enabled || got.Endpoint != initial.Endpoint || got.FeedbackEndpoint != initial.FeedbackEndpoint {
			t.Fatalf("after enabled=%v: %+v", enabled, got)
		}
	}
}
