package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitLabScanUserProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/alice/projects":
			writeJSON(t, w, []gitlabProjectRef{{ID: 9, PathWithNS: "alice/dots", DefaultBranch: "main"}})
		case "/projects/9/repository/tree":
			writeJSON(t, w, []gitlabTreeEntry{{Path: ".env", Type: "blob", ID: "b1"}})
		case "/projects/9/repository/files/.env/raw":
			_, _ = w.Write([]byte("user-secret"))
		default:
			t.Fatalf("unexpected GitLab API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)
	var got []string
	err := scanGitLab(context.Background(), Config{"token": "glpat-test", "user": "alice", "api_base": srv.URL}, func(data []byte, meta sources.Metadata) error {
		if meta.GitLab == nil || meta.GitLab.Group != "alice" || meta.GitLab.Project != "alice/dots" {
			t.Errorf("bad meta %+v", meta.GitLab)
		}
		got = append(got, string(data))
		return nil
	})
	if err != nil || len(got) != 1 || got[0] != "user-secret" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, cfg := range []Config{
		{"token": "t", "user": "a", "group": "g"},
		{"token": "t", "user": "a", "project": "g/p"},
	} {
		if err := scanGitLab(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil }); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
}
