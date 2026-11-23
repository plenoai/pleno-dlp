package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListRepositoriesGitHubOrg(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Errorf("unexpected request %s (list-only must not fetch content)", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"zeta","owner":{"login":"acme"}},{"name":"alpha","owner":{"login":"acme"},"fork":true},{"name":"beta","owner":{"login":"acme"}}]`))
	}))
	defer srv.Close()
	repos, err := ListRepositories(context.Background(), "github", Config{"org": "acme", "token": "t", "api_base": srv.URL, "include_forks": "false"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range repos {
		names = append(names, r.Name)
		if !strings.HasPrefix(r.URL, srv.URL+"/acme/") {
			t.Fatalf("url %q", r.URL)
		}
	}
	if got := strings.Join(names, ","); got != "acme/beta,acme/zeta" {
		t.Fatalf("got %s", got)
	}
}

func TestListRepositoriesGitLabGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/groups/g/projects") {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"g/b","http_url_to_repo":"https://gl/g/b.git"},{"id":2,"path_with_namespace":"g/a","http_url_to_repo":"https://gl/g/a.git"}]`))
	}))
	defer srv.Close()
	repos, err := ListRepositories(context.Background(), "gitlab", Config{"group": "g", "token": "t", "api_base": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].Name != "g/a" || repos[0].URL != "https://gl/g/a.git" {
		t.Fatalf("got %+v", repos)
	}
	if _, err := ListRepositories(context.Background(), "slack", Config{}); err == nil {
		t.Fatal("unsupported connector accepted")
	}
}
