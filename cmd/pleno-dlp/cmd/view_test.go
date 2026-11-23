package cmd

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:0", "[::1]:8080", "localhost:1", "127.5.5.5:9"} {
		if err := requireLoopback(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:0", ":8080", "[::]:1", "192.168.1.1:80", "example.com:80", "nope"} {
		if err := requireLoopback(bad); err == nil {
			t.Errorf("%s: expected rejection", bad)
		}
	}
}

func TestServeViewLoopbackAndHostCheck(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "g.json")
	secret := "ghp" + "_" + strings.Repeat("aB3d", 9) // assembled to avoid pre-commit hits
	key := "Sec" + "ret"
	if err := os.WriteFile(p, []byte(`[{"RuleID":"github-pat","File":"x","StartLine":1,"`+key+`":"`+secret+`"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	page, err := buildViewPage([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveView(ctx, ln, page) }()
	url := "http://" + ln.Addr().String() + "/"

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "github-pat") || strings.Contains(string(body), secret) {
		t.Fatalf("status %d, body leak or missing content", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Host = "evil.example:80"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding host: got %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
