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

func listOnlyServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for prefix, body := range routes {
			if strings.HasSuffix(r.URL.Path, prefix) {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		t.Errorf("unexpected request %s (list-only must not fetch content)", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListRepositoriesOtherForges(t *testing.T) {
	ctx := context.Background()

	bb := listOnlyServer(t, map[string]string{"/repositories/ws": `{"values":[{"full_name":"ws/zed","links":{"clone":[{"name":"https","href":"https://u@bitbucket.org/ws/zed.git"}]}},{"full_name":"ws/abc","links":{"clone":[{"name":"https","href":"https://bitbucket.org/ws/abc.git"}]}}]}`})
	repos, err := ListRepositories(ctx, "bitbucket", Config{"workspace": "ws", "token": "t", "api_base": bb.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].Name != "ws/abc" || repos[1].URL != "https://bitbucket.org/ws/zed.git" {
		t.Fatalf("bitbucket: %+v (userinfo must be stripped)", repos)
	}

	az := listOnlyServer(t, map[string]string{"/_apis/git/repositories": `{"value":[{"name":"r1","remoteUrl":"https://org@dev.azure.com/org/p/_git/r1","project":{"name":"p"}},{"name":"off","isDisabled":true,"project":{"name":"p"}}]}`})
	repos, err = ListRepositories(ctx, "azure-devops", Config{"org": "org", "token": "t", "base_url": az.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].Name != "p/r1" || repos[0].URL != "https://dev.azure.com/org/p/_git/r1" {
		t.Fatalf("azure-devops: %+v", repos)
	}

	hf := listOnlyServer(t, map[string]string{"/api/models": `[{"modelId":"acme/m1","author":"acme"}]`, "/api/datasets": `[{"modelId":"acme/d1","author":"acme"}]`})
	repos, err = ListRepositories(ctx, "huggingface", Config{"org": "acme", "api_base": hf.URL, "repo_types": "model,dataset,bucket"})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].Name != "acme/m1" || repos[1].Name != "datasets/acme/d1" || !strings.HasSuffix(repos[1].URL, "/datasets/acme/d1.git") {
		t.Fatalf("huggingface: %+v", repos)
	}

	gt := listOnlyServer(t, map[string]string{"/repos/o/r": `{"full_name":"o/r"}`})
	repos, err = ListRepositories(ctx, "forgejo", Config{"repo": "o/r", "token": "t", "api_base": gt.URL + "/api/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].URL != gt.URL+"/o/r.git" {
		t.Fatalf("forgejo: %+v", repos)
	}
	if _, err := ListRepositories(ctx, "gitea", Config{"repo": "bad", "token": "t", "api_base": gt.URL}); err == nil {
		t.Fatal("malformed repo accepted")
	}
}
