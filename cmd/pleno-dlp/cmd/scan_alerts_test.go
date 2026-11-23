package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Split so the pre-commit secret scan does not flag the fixture.
var alertFixtureKey = "AKIA" + "1234567890ABCDEF"

func TestScanAlertWebhookPostsRedactedSummary(t *testing.T) {
	resetCommandFlags(t)
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "leak.env"), []byte("AWS_ACCESS_KEY_ID="+alertFixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "filesystem", dir, "--no-verify", "--quiet", "--fail-on=critical",
		"--alert-min-severity=info", "--alert-webhook", srv.URL + "/a", "--alert-webhook", srv.URL + "/b"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("got %d posts, want 2; stderr=%s", len(bodies), stderr.String())
	}
	for _, b := range bodies {
		var s struct {
			Total int `json:"total"`
		}
		if json.Unmarshal(b, &s) != nil || s.Total < 1 {
			t.Fatalf("bad payload %s", b)
		}
		if strings.Contains(string(b), alertFixtureKey) {
			t.Fatalf("payload leaks secret: %s", b)
		}
	}
}

func TestScanAlertWebhookFailureDoesNotChangeExitCode(t *testing.T) {
	resetCommandFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "leak.env"), []byte("AWS_ACCESS_KEY_ID="+alertFixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "filesystem", dir, "--no-verify", "--quiet", "--fail-on=critical",
		"--alert-min-severity=info", "--alert-webhook", srv.URL + "/services/TOKEN"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stderr.String(), "alert delivery failed") || strings.Contains(stderr.String(), "TOKEN") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestScanRejectsInvalidAlertFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--alert-webhook", "ftp://x.example/y"},
		{"--alert-min-severity", "any"},
	} {
		resetCommandFlags(t)
		var out bytes.Buffer
		Root.SetOut(&out)
		Root.SetErr(&out)
		Root.SetArgs(append([]string{"scan", "filesystem", t.TempDir(), "--no-verify"}, args...))
		if err := Root.Execute(); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}

func TestScanAlertOnAlwaysAndPreventEmpty(t *testing.T) {
	run := func(t *testing.T, content string, extra ...string) []string {
		t.Helper()
		resetCommandFlags(t)
		var mu sync.Mutex
		var bodies []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
		}))
		defer srv.Close()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "f.env"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		Root.SetOut(&out)
		Root.SetErr(&stderr)
		args := append([]string{"scan", "filesystem", dir, "--no-verify", "--quiet", "--fail-on=critical",
			"--alert-webhook", srv.URL + "/hook"}, extra...)
		Root.SetArgs(args)
		if err := Root.Execute(); err != nil {
			t.Fatalf("scan: %v\n%s", err, stderr.String())
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
	if got := run(t, "nothing here\n"); len(got) != 0 {
		t.Fatalf("clean scan posted %d alerts", len(got))
	}
	got := run(t, "nothing here\n", "--alert-on=always", "--alert-report-url=https://ci.example/run/1")
	if len(got) != 1 || !strings.Contains(got[0], `"total":0`) || !strings.Contains(got[0], "https://ci.example/run/1") {
		t.Fatalf("always heartbeat: %v", got)
	}
	leak := "AWS_ACCESS_KEY_ID=" + alertFixtureKey + "\n"
	// only-active drops the unverified finding; prevent-empty (default) skips.
	if got := run(t, leak, "--alert-min-severity=info", "--alert-finding-filter=only-active"); len(got) != 0 {
		t.Fatalf("prevent-empty posted: %v", got)
	}
	got = run(t, leak, "--alert-min-severity=info", "--alert-finding-filter=only-active", "--alert-prevent-empty=false")
	if len(got) != 1 || !strings.Contains(got[0], `"total":0`) {
		t.Fatalf("prevent-empty=false: %v", got)
	}
	if err := func() error {
		resetCommandFlags(t)
		Root.SetArgs([]string{"scan", "filesystem", t.TempDir(), "--alert-detail=loud"})
		return Root.Execute()
	}(); err == nil || !strings.Contains(err.Error(), "--alert-detail") {
		t.Fatalf("want --alert-detail error, got %v", err)
	}
}
