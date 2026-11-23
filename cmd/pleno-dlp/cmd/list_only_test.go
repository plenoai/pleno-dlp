package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestScanOutputFileAndUserAgentSuffix(t *testing.T) {
	resetCommandFlags(t)
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		_, _ = w.Write([]byte(`{"values":[{"full_name":"ws/a","links":{"clone":[{"name":"https","href":"https://bitbucket.example/ws/a.git"}]}}]}`))
	}))
	defer srv.Close()
	outPath := filepath.Join(t.TempDir(), "repos.txt")
	var stdout, stderr bytes.Buffer
	Root.SetOut(&stdout)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "bitbucket", "--workspace", "ws", "--token", "t", "--api-base", srv.URL,
		"--list-only", "-o", outPath, "--user-agent-suffix", "acme-secops/1"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "https://bitbucket.example/ws/a.git" || stdout.Len() != 0 {
		t.Fatalf("file %q stdout %q", got, stdout.String())
	}
	if fi, _ := os.Stat(outPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if !strings.HasSuffix(ua, " acme-secops/1") {
		t.Fatalf("User-Agent %q", ua)
	}
	resetCommandFlags(t)
	Root.SetArgs([]string{"scan", "bitbucket", "--workspace", "ws", "--token", "t", "--api-base", srv.URL, "--list-only", "--user-agent-suffix", "x\r\nX-Evil: 1"})
	if err := Root.Execute(); err == nil {
		t.Fatal("header-injecting suffix accepted")
	}
}
