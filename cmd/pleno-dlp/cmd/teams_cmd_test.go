package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanTeamsEndToEnd(t *testing.T) {
	resetCommandFlags(t)
	awsKey := "AKIA" + "QYLPMN5HHHFPZAM2" // split so the pre-commit hook does not flag the fixture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/teams/t1/channels":
			_, _ = w.Write([]byte(`{"value":[{"id":"c1","displayName":"ops"}]}`))
		case "/teams/t1/channels/c1/messages":
			_, _ = w.Write([]byte(`{"value":[{"id":"m1","lastModifiedDateTime":"2026-01-01T00:00:00Z","body":{"content":"aws ` + awsKey + `"}}]}`))
		default:
			_, _ = w.Write([]byte(`{"value":[]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("MS_GRAPH_TOKEN", "g")
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--no-verify", "--format", "json", "teams", "--team", "t1", "--base-url", srv.URL})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "findings detected") {
		t.Fatalf("want findings-detected exit, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), `"event_id": "t1/c1/m1"`) {
		t.Fatalf("missing teams finding:\n%s", out.String())
	}
}
