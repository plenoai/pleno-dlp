package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestForgeConnectorRegistrations(t *testing.T) {
	cases := map[string]sources.SourceType{
		"forgejo":   sources.SourceForgejo,
		"gitea":     sources.SourceGitea,
		"gogs":      sources.SourceGogs,
		"gitbucket": sources.SourceGitbucket,
		"codeberg":  sources.SourceCodeberg,
		"onedev":    sources.SourceOneDev,
		"codebase":  sources.SourceCodebase,
		"pagure":    sources.SourcePagure,
	}
	for name, wantType := range cases {
		conn, ok := Get(name)
		if !ok {
			t.Fatalf("Get(%q) ok = false, want true", name)
		}
		if conn.Scan == nil {
			t.Fatalf("Get(%q).Scan = nil, want scan implementation", name)
		}
		if conn.SourceType != wantType {
			t.Fatalf("Get(%q).SourceType = %s, want %s", name, conn.SourceType, wantType)
		}
	}
}

func TestGiteaCompatibleIncrementalScanEmitsOnlyChangedComments(t *testing.T) {
	comments := []giteaComment{
		{ID: 1, Body: "old secret"},
		{ID: 2, Body: "keep secret"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/issues/comments" {
			t.Fatalf("unexpected Gitea API path: %s", r.URL.String())
		}
		writeJSON(t, w, comments)
	}))
	defer srv.Close()

	cfg := Config{"token": "gitea-token", "repo": "acme/widget", "api_base": srv.URL}
	var first []string
	if err := scanGiteaCompatible(context.Background(), giteaProvider{name: "gitea", typ: sources.SourceGitea}, cfg, func(data []byte, _ sources.Metadata) error {
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanGiteaCompatible: %v", err)
	}
	if got, want := strings.Join(first, ","), "old secret,keep secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	comments = []giteaComment{
		{ID: 1, Body: "new secret"},
		{ID: 2, Body: "keep secret"},
	}
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)
	var second []string
	if err := scanGiteaCompatible(context.Background(), giteaProvider{name: "gitea", typ: sources.SourceGitea}, cfg, func(data []byte, _ sources.Metadata) error {
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanGiteaCompatible: %v", err)
	}
	if got, want := strings.Join(second, ","), "new secret"; got != want {
		t.Fatalf("second emitted %q, want only changed comment %q", got, want)
	}
}
