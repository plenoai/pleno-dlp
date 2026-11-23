package blastradius_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/blastradius"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/aws"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gcp"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/github"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gitlab"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/slack"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func assertSchema(t *testing.T, am *detectors.AccessMap) {
	t.Helper()
	b, err := json.Marshal(am)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"schema", "provider", "identity", "permissions", "resources", "privileged", "limitations"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %q in %s", k, b)
		}
	}
	for _, k := range []string{"permissions", "resources", "limitations"} {
		if m[k] == nil {
			t.Fatalf("%q must be an array, got null: %s", k, b)
		}
	}
	if m["schema"] != detectors.AccessMapSchemaVersion {
		t.Fatalf("schema = %v", m["schema"])
	}
}

func TestGitHub(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_x" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			_, _ = w.Write([]byte(`{"login":"octo","id":7,"type":"User"}`))
		case "/user/orgs":
			_, _ = w.Write([]byte(`[{"login":"acme"}]`))
		case "/user/repos":
			_, _ = w.Write([]byte(`[{"full_name":"acme/app","permissions":{"admin":false,"push":true,"pull":true}}]`))
		}
	})
	am, err := github.Mapper{BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "ghp_x"})
	if err != nil {
		t.Fatal(err)
	}
	assertSchema(t, am)
	if am.Identity.Name != "octo" || !slices.Equal(am.Permissions, []string{"repo", "read:org"}) || !am.Privileged {
		t.Fatalf("unexpected %+v", am)
	}
	if len(am.Resources) != 2 || !slices.Equal(am.Resources[1].Permissions, []string{"push", "pull"}) {
		t.Fatalf("resources %+v", am.Resources)
	}
	if _, err := (github.Mapper{BaseURL: s.URL}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "bad"}); err == nil {
		t.Fatal("expected error for rejected token")
	}
}

func TestGitLab(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-x" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v4/user":
			_, _ = w.Write([]byte(`{"id":3,"username":"dev"}`))
		case "/api/v4/personal_access_tokens/self":
			_, _ = w.Write([]byte(`{"scopes":["read_api"]}`))
		case "/api/v4/projects":
			_, _ = w.Write([]byte(`[{"path_with_namespace":"g/p","permissions":{"project_access":{"access_level":30},"group_access":{"access_level":40}}}]`))
		}
	})
	am, err := gitlab.Mapper{BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "glpat-x"})
	if err != nil {
		t.Fatal(err)
	}
	assertSchema(t, am)
	if am.Identity.Name != "dev" || am.Resources[0].Permissions[0] != "maintainer" || !am.Privileged {
		t.Fatalf("unexpected %+v", am)
	}
}

func TestSlack(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer xoxb-x" {
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			return
		}
		w.Header().Set("X-OAuth-Scopes", "chat:write,channels:read")
		_, _ = w.Write([]byte(`{"ok":true,"team":"Acme","team_id":"T1","user":"bot","user_id":"U1","bot_id":"B1"}`))
	})
	am, err := slack.Mapper{BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "xoxb-x"})
	if err != nil {
		t.Fatal(err)
	}
	assertSchema(t, am)
	if am.Identity.Type != "bot" || am.Identity.Account != "T1" || !am.Privileged || len(am.Permissions) != 2 {
		t.Fatalf("unexpected %+v", am)
	}
	if _, err := (slack.Mapper{BaseURL: s.URL}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "bad"}); err == nil || !strings.Contains(err.Error(), "invalid_auth") {
		t.Fatalf("err = %v", err)
	}
}

func TestAWSUser(t *testing.T) {
	var actions []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=AKIAEXAMPLE/") {
			w.WriteHeader(403)
			return
		}
		_ = r.ParseForm()
		a := r.Form.Get("Action")
		actions = append(actions, a)
		switch a {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ops/alice</Arn><UserId>AID</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		case "ListAttachedUserPolicies":
			if r.Form.Get("UserName") != "alice" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`<R><ListAttachedUserPoliciesResult><AttachedPolicies><member><PolicyName>ReadOnlyAccess</PolicyName><PolicyArn>arn:x</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedUserPoliciesResult></R>`))
		case "ListUserPolicies":
			_, _ = w.Write([]byte(`<R><ListUserPoliciesResult><PolicyNames><member>inline-s3</member></PolicyNames><IsTruncated>true</IsTruncated></ListUserPoliciesResult></R>`))
		case "ListGroupsForUser":
			_, _ = w.Write([]byte(`<R><ListGroupsForUserResult><Groups><member><GroupName>admins</GroupName></member></Groups></ListGroupsForUserResult></R>`))
		case "ListAttachedGroupPolicies":
			_, _ = w.Write([]byte(`<R><ListAttachedGroupPoliciesResult><AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName></member></AttachedPolicies></ListAttachedGroupPoliciesResult></R>`))
		case "ListGroupPolicies":
			w.WriteHeader(403)
		}
	})
	m := aws.Mapper{STSURL: s.URL, IAMURL: s.URL}
	am, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: "AKIAEXAMPLE", Secondary: "sk"})
	if err != nil {
		t.Fatal(err)
	}
	assertSchema(t, am)
	if am.Identity.Type != "user" || am.Identity.Name != "alice" || am.Identity.Account != "123456789012" {
		t.Fatalf("identity %+v", am.Identity)
	}
	want := []string{"policy:ReadOnlyAccess", "policy:inline-s3", "policy:AdministratorAccess"}
	if !slices.Equal(am.Permissions, want) || !am.Privileged {
		t.Fatalf("permissions %v privileged %v", am.Permissions, am.Privileged)
	}
	joined := strings.Join(am.Limitations, "|")
	if !strings.Contains(joined, "ListUserPolicies: result truncated") || !strings.Contains(joined, "ListGroupPolicies: iam:ListGroupPolicies: HTTP 403") {
		t.Fatalf("limitations %v", am.Limitations)
	}
	if _, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: "AKIAEXAMPLE"}); err == nil {
		t.Fatal("expected error without secret key")
	}
}

func TestAWSAssumedRole(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<X><GetCallerIdentityResult><Arn>arn:aws:sts::1:assumed-role/R/s</Arn><Account>1</Account></GetCallerIdentityResult></X>`))
	})
	am, err := aws.Mapper{STSURL: s.URL, IAMURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "AKIA", Secondary: "s"})
	if err != nil || am.Identity.Type != "assumed-role" || len(am.Limitations) != 1 {
		t.Fatalf("am %+v err %v", am, err)
	}
}

func gcpKey(t *testing.T, tokenURI string) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj-a", "client_email": "sa@proj-a.iam.gserviceaccount.com",
		"client_id": "42", "private_key": pemKey, "private_key_id": "kid", "token_uri": tokenURI,
	})
	return string(b)
}

func TestGCP(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"ya29.t","token_type":"Bearer","expires_in":3600}`))
			return
		case r.Header.Get("Authorization") != "Bearer ya29.t":
			w.WriteHeader(401)
		case r.URL.Path == "/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"projectId":"proj-a"},{"projectId":"proj-b"}]}`))
		case r.URL.Path == "/v1/projects/proj-a:testIamPermissions":
			_, _ = w.Write([]byte(`{"permissions":["storage.buckets.list","iam.serviceAccountKeys.create"]}`))
		case r.URL.Path == "/v1/projects/proj-b:testIamPermissions":
			_, _ = w.Write([]byte(`{}`))
		}
	})
	m := gcp.Mapper{ResourceManagerURL: s.URL, IAMURL: s.URL, Client: s.Client()}
	am, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: gcpKey(t, s.URL+"/token")})
	if err != nil {
		t.Fatal(err)
	}
	assertSchema(t, am)
	if am.Identity.Name != "sa@proj-a.iam.gserviceaccount.com" || !am.Privileged || len(am.Resources) != 2 || len(am.Permissions) != 2 {
		t.Fatalf("unexpected %+v", am)
	}
	if _, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: "{}"}); err == nil {
		t.Fatal("expected error for non-key input")
	}
}

func TestGCPHierarchyAndImpersonation(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"ya29.t","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer ya29.t" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/projects":
			if r.URL.Query().Get("pageToken") == "" {
				_, _ = w.Write([]byte(`{"projects":[{"projectId":"proj-a"}],"nextPageToken":"p2"}`))
				return
			}
			_, _ = w.Write([]byte(`{"projects":[{"projectId":"proj-b"}]}`))
		case "/v1/projects/proj-a:testIamPermissions", "/v1/projects/proj-b:testIamPermissions":
			_, _ = w.Write([]byte(`{"permissions":["storage.buckets.list"]}`))
		case "/v1/projects/proj-a:getAncestry", "/v1/projects/proj-b:getAncestry":
			_, _ = w.Write([]byte(`{"ancestor":[{"resourceId":{"type":"project","id":"x"}},{"resourceId":{"type":"folder","id":"55"}},{"resourceId":{"type":"organization","id":"9"}}]}`))
		case "/v3/folders/55:testIamPermissions":
			_, _ = w.Write([]byte(`{"permissions":["resourcemanager.folders.get"]}`))
		case "/v3/organizations/9:testIamPermissions":
			_, _ = w.Write([]byte(`{"permissions":["resourcemanager.organizations.setIamPolicy"]}`))
		case "/v1/projects/proj-a/serviceAccounts":
			_, _ = w.Write([]byte(`{"accounts":[{"email":"sa@proj-a.iam.gserviceaccount.com"},{"email":"deployer@proj-a.iam.gserviceaccount.com"}]}`))
		case "/v1/projects/proj-b/serviceAccounts":
			w.WriteHeader(403)
		case "/v1/projects/-/serviceAccounts/deployer@proj-a.iam.gserviceaccount.com:testIamPermissions":
			_, _ = w.Write([]byte(`{"permissions":["iam.serviceAccounts.getAccessToken"]}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	m := gcp.Mapper{ResourceManagerURL: s.URL, IAMURL: s.URL, Client: s.Client()}
	am, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: gcpKey(t, s.URL+"/token")})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, r := range am.Resources {
		got[r.Type+":"+r.Name] = r.Permissions
	}
	for k, want := range map[string][]string{
		"project:proj-b":               {"storage.buckets.list"},
		"folder:folders/55":            {"resourcemanager.folders.get"},
		"organization:organizations/9": {"resourcemanager.organizations.setIamPolicy"},
		"impersonable_service_account:deployer@proj-a.iam.gserviceaccount.com": {"iam.serviceAccounts.getAccessToken"},
	} {
		if !slices.Equal(got[k], want) {
			t.Fatalf("%s = %v (all %v)", k, got[k], got)
		}
	}
	if _, self := got["impersonable_service_account:sa@proj-a.iam.gserviceaccount.com"]; self || !am.Privileged {
		t.Fatalf("self-probe or privilege wrong: %+v", am)
	}
	if !strings.Contains(strings.Join(am.Limitations, "|"), "serviceAccounts proj-b") {
		t.Fatalf("limitations %v", am.Limitations)
	}
}

func TestRegistryMapResult(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"login":"octo","id":1}`))
	})
	r := blastradius.NewRegistry(blastradius.Provider{Name: "github", Mapper: github.Mapper{BaseURL: s.URL}, Detectors: []detectors.DetectorType{detectors.GitHub}})
	if am, err := r.MapResult(context.Background(), detectors.Result{DetectorType: detectors.GitHub, Raw: []byte("t")}); am != nil || err != nil {
		t.Fatal("unverified results must not be mapped")
	}
	if am, _ := r.MapResult(context.Background(), detectors.Result{DetectorType: detectors.GitLab, Raw: []byte("t"), Verified: true}); am != nil {
		t.Fatal("unsupported detector must not be mapped")
	}
	am, err := r.MapResult(context.Background(), detectors.Result{DetectorType: detectors.GitHub, Raw: []byte("t"), Verified: true})
	if err != nil || am.Identity.Name != "octo" {
		t.Fatalf("am %+v err %v", am, err)
	}
	if got := blastradius.Default().Names(); !slices.Equal(got, []string{"alibaba", "anthropic", "asana", "aws", "azure", "azure-storage", "bitbucket", "buildkite", "circleci", "confluence", "digitalocean", "fastly", "gcp", "gitea", "github", "gitlab", "harness", "huggingface", "jira", "openai", "pinecone", "sendgrid", "slack", "stripe", "terraformcloud"}) {
		t.Fatalf("names %v", got)
	}
}

func TestCredentialParsing(t *testing.T) {
	c := blastradius.CredentialFromResult(detectors.Result{DetectorType: detectors.AWS, Raw: []byte("AKIA"), RawV2: []byte("sk")})
	if c.Secret != "AKIA" || c.Secondary != "sk" {
		t.Fatalf("%+v", c)
	}
	for _, tc := range []struct {
		prov, in    string
		secret, sec string
		wantErr     bool
	}{
		{"github", "ghp_x\n", "ghp_x", "", false},
		{"gitlab", `{"token":"glpat","api_endpoint":"https://gl.example"}`, "glpat", "", false},
		{"aws", "AKIA:sk", "AKIA", "sk", false},
		{"aws", `{"access_key_id":"AKIA","secret_access_key":"sk"}`, "AKIA", "sk", false},
		{"aws", "AKIA", "", "", true},
		{"slack", "  ", "", "", true},
		{"github", `{"api_endpoint":"x"}`, "", "", true},
	} {
		c, err := blastradius.ParseCredentialFile(tc.prov, []byte(tc.in))
		if (err != nil) != tc.wantErr || (!tc.wantErr && (c.Secret != tc.secret || c.Secondary != tc.sec)) {
			t.Errorf("%s %q: %+v %v", tc.prov, tc.in, c, err)
		}
	}
}
