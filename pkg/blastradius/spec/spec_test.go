package spec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type route struct {
	body string
	hdr  map[string]string
}

func fixture(t *testing.T, wantAuth string, routes map[string]route) *httptest.Server {
	t.Helper()
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization") + r.Header.Get("x-api-key") + r.Header.Get("Circle-Token") + r.Header.Get("Fastly-Key") + r.Header.Get("Api-Key")
		if auth != wantAuth {
			w.WriteHeader(401)
			return
		}
		rt, ok := routes[r.URL.RequestURI()]
		if !ok {
			rt, ok = routes[r.URL.Path]
		}
		if !ok {
			w.WriteHeader(404)
			return
		}
		for k, v := range rt.hdr {
			w.Header().Set(k, strings.ReplaceAll(v, "{base}", s.URL))
		}
		_, _ = w.Write([]byte(strings.ReplaceAll(rt.body, "{base}", s.URL)))
	}))
	t.Cleanup(s.Close)
	return s
}

func resNames(am *detectors.AccessMap, typ string) []string {
	var out []string
	for _, r := range am.Resources {
		if r.Type == typ {
			out = append(out, r.Name)
		}
	}
	return out
}

func TestProviders(t *testing.T) {
	cases := []struct {
		name     string
		spec     Spec
		cred     detectors.AccessCredential
		auth     string
		routes   map[string]route
		identity string
		priv     bool
		perms    []string
		res      map[string][]string
		limit    string
	}{
		{name: "openai", spec: OpenAI, cred: detectors.AccessCredential{Secret: "sk-x"}, auth: "Bearer sk-x",
			routes: map[string]route{
				"/v1/me":                    {body: `{"id":"user-1","email":"a@b","orgs":{"data":[{"title":"Acme","role":"owner"}]}}`},
				"/v1/organization/projects": {body: `{"data":[{"name":"p1"}]}`},
			}, identity: "a@b", priv: true, res: map[string][]string{"organization": {"Acme"}, "project": {"p1"}}},
		{name: "anthropic", spec: Anthropic, cred: detectors.AccessCredential{Secret: "sk-ant-api03-x"}, auth: "sk-ant-api03-x",
			routes: map[string]route{"/v1/models": {body: `{"data":[{"id":"claude-x"}]}`}},
			res:    map[string][]string{"model": {"claude-x"}}, limit: "workspace: "},
		{name: "huggingface", spec: HuggingFace, cred: detectors.AccessCredential{Secret: "hf_x"}, auth: "Bearer hf_x",
			routes:   map[string]route{"/api/whoami-v2": {body: `{"id":"1","name":"me","type":"user","auth":{"accessToken":{"role":"write"}},"orgs":[{"name":"o","roleInOrg":"read"}]}`}},
			identity: "me", priv: true, perms: []string{"write"}, res: map[string][]string{"organization": {"o"}}},
		{name: "buildkite link pagination", spec: Buildkite, cred: detectors.AccessCredential{Secret: "bk"}, auth: "Bearer bk",
			routes: map[string]route{
				"/v2/user":                       {body: `{"id":"u","email":"e@x"}`},
				"/v2/access-token":               {body: `{"scopes":["read_builds","write_pipelines"]}`},
				"/v2/organizations?per_page=100": {body: `[{"slug":"a"}]`, hdr: map[string]string{"Link": `<{base}/v2/organizations?page=2>; rel="next"`}},
				"/v2/organizations?page=2":       {body: `[{"slug":"b"}]`},
			}, identity: "e@x", priv: true, perms: []string{"read_builds", "write_pipelines"}, res: map[string][]string{"organization": {"a", "b"}}},
		{name: "gitea page param", spec: Gitea, cred: detectors.AccessCredential{Secret: "g", Extra: map[string]string{}}, auth: "token g",
			routes: map[string]route{
				"/api/v1/user":                       {body: `{"id":3,"login":"me","is_admin":false}`},
				"/api/v1/user/orgs?limit=50":         {body: `[]`},
				"/api/v1/user/repos?limit=50":        {body: `[{"full_name":"me/a","permissions":{"admin":true,"push":true,"pull":true}}]`},
				"/api/v1/user/repos?limit=50&page=2": {body: `[]`},
			}, identity: "me", priv: true, res: map[string][]string{"repository": {"me/a"}}},
		{name: "bitbucket next field", spec: Bitbucket, cred: detectors.AccessCredential{Secret: "bb"}, auth: "Bearer bb",
			routes: map[string]route{
				"/2.0/user": {body: `{"uuid":"{u}","username":"me","type":"user"}`, hdr: map[string]string{"X-OAuth-Scopes": "repository, account"}},
				"/2.0/user/permissions/workspaces?pagelen=100":   {body: `{"values":[{"permission":"member","workspace":{"slug":"w1"}}],"next":"{base}/2.0/user/permissions/workspaces?page=2"}`},
				"/2.0/user/permissions/workspaces?page=2":        {body: `{"values":[{"permission":"owner","workspace":{"slug":"w2"}}]}`},
				"/2.0/user/permissions/repositories?pagelen=100": {body: `{"values":[]}`},
			}, identity: "me", priv: true, perms: []string{"repository", "account"}, res: map[string][]string{"workspace": {"w1", "w2"}}},
		{name: "bitbucket app password", spec: Bitbucket, cred: detectors.AccessCredential{Secret: "pw", Extra: map[string]string{"username": "me"}}, auth: "Basic bWU6cHc=",
			routes:   map[string]route{"/2.0/user": {body: `{"uuid":"u","username":"me"}`}, "/2.0/user/permissions/workspaces": {body: `{"values":[]}`}, "/2.0/user/permissions/repositories": {body: `{"values":[]}`}},
			identity: "me", limit: "token scopes not reported"},
		{name: "jira offset/next", spec: Jira, cred: detectors.AccessCredential{Secret: "t", Extra: map[string]string{"email": "a@b"}}, auth: "Basic YUBiOnQ=",
			routes: map[string]route{
				"/rest/api/3/myself":         {body: `{"accountId":"acc","emailAddress":"a@b","accountType":"atlassian"}`},
				"/rest/api/3/mypermissions":  {body: `{"permissions":{"ADMINISTER":{"havePermission":true}}}`},
				"/rest/api/3/project/search": {body: `{"values":[{"key":"ABC"}]}`},
			}, identity: "a@b", res: map[string][]string{"project": {"ABC"}}},
		{name: "confluence offset", spec: Confluence, cred: detectors.AccessCredential{Secret: "t", Extra: map[string]string{"email": "a@b"}}, auth: "Basic YUBiOnQ=",
			routes: map[string]route{
				"/wiki/rest/api/user/current":            {body: `{"accountId":"acc","publicName":"A"}`},
				"/wiki/rest/api/space?limit=100":         {body: `{"results":[{"key":"S1"},{"key":"S2"}]}`},
				"/wiki/rest/api/space?limit=100&start=2": {body: `{"results":[]}`},
			}, identity: "A", res: map[string][]string{"space": {"S1", "S2"}}},
		{name: "stripe live", spec: Stripe, cred: detectors.AccessCredential{Secret: "sk_live_x"}, auth: "Basic c2tfbGl2ZV94Og==",
			routes: map[string]route{"/v1/account": {body: `{"id":"acct_1","email":"s@x"}`}}, identity: "s@x", priv: true},
		{name: "fastly", spec: Fastly, cred: detectors.AccessCredential{Secret: "f"}, auth: "f",
			routes:   map[string]route{"/current_user": {body: `{"id":"u","login":"l","role":"user","customer_id":"c"}`}, "/tokens/self": {body: `{"scopes":["global:read"]}`}},
			identity: "l", perms: []string{"global:read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t, tc.auth, tc.routes)
			am, err := Mapper{Spec: tc.spec, BaseURL: s.URL}.MapAccess(context.Background(), tc.cred)
			if err != nil {
				t.Fatal(err)
			}
			if am.Schema != detectors.AccessMapSchemaVersion || am.Permissions == nil || am.Resources == nil || am.Limitations == nil {
				t.Fatalf("schema/arrays: %+v", am)
			}
			if tc.identity != "" && am.Identity.Name != tc.identity {
				t.Fatalf("identity %+v", am.Identity)
			}
			if am.Privileged != tc.priv {
				t.Fatalf("privileged = %v: %+v", am.Privileged, am)
			}
			if tc.perms != nil && !slices.Equal(am.Permissions, tc.perms) {
				t.Fatalf("perms %v", am.Permissions)
			}
			for typ, want := range tc.res {
				if got := resNames(am, typ); !slices.Equal(got, want) {
					t.Fatalf("%s = %v, want %v", typ, got, want)
				}
			}
			if tc.limit != "" && !strings.Contains(strings.Join(am.Limitations, "|"), tc.limit) {
				t.Fatalf("limitations %v", am.Limitations)
			}
		})
	}
}

func TestRequireEndpointAndHTTPS(t *testing.T) {
	if _, err := (Mapper{Spec: Gitea}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "x"}); err == nil || !strings.Contains(err.Error(), "api_endpoint") {
		t.Fatalf("want api_endpoint error, got %v", err)
	}
	_, err := (Mapper{Spec: Gitea}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "x", Extra: map[string]string{"api_endpoint": "http://gitea.internal"}})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http endpoint must be refused, got %v", err)
	}
}

func TestCrossOriginNextRefused(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("credential sent cross-origin: %s", r.URL)
	}))
	defer other.Close()
	s := fixture(t, "Bearer bb", map[string]route{
		"/2.0/user": {body: `{"uuid":"u","username":"me"}`},
		"/2.0/user/permissions/workspaces?pagelen=100":   {body: `{"values":[{"workspace":{"slug":"w"}}],"next":"` + other.URL + `/steal"}`},
		"/2.0/user/permissions/repositories?pagelen=100": {body: `{"values":[]}`},
	})
	am, err := Mapper{Spec: Bitbucket, BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "bb"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(am.Limitations, "|"), "workspace listing capped") {
		t.Fatalf("limitations %v", am.Limitations)
	}
}

func TestMaxItemsCap(t *testing.T) {
	sp := Asana
	sp.MaxItems = 1
	s := fixture(t, "Bearer a", map[string]route{"/api/1.0/users/me": {body: `{"data":{"gid":"1","name":"n","workspaces":[{"name":"a"},{"name":"b"}]}}`}})
	am, err := Mapper{Spec: sp, BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(am.Resources) != 1 || !strings.Contains(strings.Join(am.Limitations, "|"), "capped at 1") {
		t.Fatalf("%+v", am)
	}
}

func TestIdentityFailureIsError(t *testing.T) {
	s := fixture(t, "Bearer right", map[string]route{})
	if _, err := (Mapper{Spec: OpenAI, BaseURL: s.URL}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "wrong"}); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("want redacted error, got %v", err)
	}
}
