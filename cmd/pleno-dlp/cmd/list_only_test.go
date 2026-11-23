package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanListOnly(t *testing.T) {
	resetCommandFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"g/a","http_url_to_repo":"https://gl.example/g/a.git"}]`))
	}))
	defer srv.Close()
	var out, stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "gitlab", "--group", "g", "--token", "t", "--api-base", srv.URL, "--list-only"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("list-only: %v\n%s", err, stderr.String())
	}
	if strings.TrimSpace(out.String()) != "https://gl.example/g/a.git" {
		t.Fatalf("stdout %q", out.String())
	}
	resetCommandFlags(t)
	Root.SetArgs([]string{"scan", "filesystem", t.TempDir(), "--list-only"})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "--list-only") {
		t.Fatalf("want unsupported error, got %v", err)
	}
}
