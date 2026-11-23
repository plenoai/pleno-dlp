package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScanPostmanEndToEnd drives `scan postman` against a fake Postman API
// and asserts a secret inside a collection surfaces as a finding.
func TestScanPostmanEndToEnd(t *testing.T) {
	resetCommandFlags(t)
	awsKey := "AKIA" + "QYLPMN5HHHFPZAM2" // split so the pre-commit hook does not flag the fixture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "pmak-test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/workspaces":
			_, _ = w.Write([]byte(`{"workspaces":[{"id":"ws1","name":"Team"}]}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"collections":[{"uid":"c1","name":"API"}]}`))
		case "/collections/c1":
			_, _ = w.Write([]byte(`{"collection":{"variable":[{"key":"aws","value":"` + awsKey + `"}]}}`))
		case "/environments":
			_, _ = w.Write([]byte(`{"environments":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--no-verify", "--format", "json", "postman", "--api-key", "pmak-test", "--base-url", srv.URL})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "findings detected") {
		t.Fatalf("scan postman: want findings-detected exit, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), `"host": "`+srv.URL+`"`) {
		t.Errorf("finding host should be the configured base URL %s:\n%s", srv.URL, out.String())
	}
	if !strings.Contains(out.String(), "c1") || !strings.Contains(strings.ToLower(out.String()), "aws") {
		t.Fatalf("expected AWS finding from collection c1, got:\n%s", out.String())
	}
}

func TestScanPostmanRequiresAPIKey(t *testing.T) {
	resetCommandFlags(t)
	t.Setenv("POSTMAN_API_KEY", "")
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "postman"})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "POSTMAN_API_KEY") {
		t.Fatalf("want missing api key error, got %v", err)
	}
}
