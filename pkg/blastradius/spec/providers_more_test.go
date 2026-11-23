package spec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// mux routes "METHOD path" (and, for GraphQL, "POST path#<substring of
// query>") to bodies and records every request.
func mux(t *testing.T, check func(r *http.Request, body string) bool, routes map[string]string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if check != nil && !check(r, body) {
			w.WriteHeader(401)
			return
		}
		for k, v := range routes {
			m, rest, _ := strings.Cut(k, " ")
			p, frag, _ := strings.Cut(rest, "#")
			if m == r.Method && (p == r.URL.Path || p == r.URL.RequestURI()) && (frag == "" || strings.Contains(body, frag)) {
				_, _ = w.Write([]byte(v))
				return
			}
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(s.Close)
	return s
}

func run(t *testing.T, sp Spec, s *httptest.Server, cred detectors.AccessCredential) *detectors.AccessMap {
	t.Helper()
	am, err := Mapper{Spec: sp, BaseURL: s.URL}.MapAccess(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	return am
}

func TestAlgolia(t *testing.T) {
	s := mux(t, func(r *http.Request, _ string) bool {
		return r.Header.Get("X-Algolia-API-Key") == "k/1" && r.Header.Get("X-Algolia-Application-Id") == "APP123"
	}, map[string]string{
		"GET /1/keys/k%2F1": `{"acl":["search","deleteIndex"],"description":"ci","indexes":["prod_*"]}`,
		"GET /1/indexes":    `{"items":[{"name":"prod_users"}]}`,
	})
	am := run(t, Algolia, s, detectors.AccessCredential{Secret: "k/1", Extra: map[string]string{"application_id": "APP123"}})
	if !am.Privileged || am.Identity.ID != "APP123" || !slices.Equal(resNames(am, "index"), []string{"prod_users"}) || !slices.Equal(resNames(am, "index_restriction"), []string{"prod_*"}) {
		t.Fatalf("%+v", am)
	}
	if _, err := (Mapper{Spec: Algolia}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "k", Extra: map[string]string{"application_id": "evil.com/x"}}); err == nil {
		t.Fatal("invalid application id must be refused before any request")
	}
}

func TestArtifactoryActivity(t *testing.T) {
	s := mux(t, func(r *http.Request, _ string) bool { return r.Header.Get("Authorization") == "Bearer jf" }, map[string]string{
		"GET /artifactory/api/security/current": `{"name":"bob","email":"b@x","admin":true,"groups":["readers"]}`,
		"GET /artifactory/api/repositories":     `[{"key":"libs-release","type":"LOCAL"}]`,
		"GET /access/api/v1/tokens/me":          `{"last_used":1700000000}`,
	})
	am := run(t, Artifactory, s, detectors.AccessCredential{Secret: "jf"})
	if !am.Privileged || am.Identity.Name != "b@x" || am.Activity == nil || am.Activity.LastUsed != "2023-11-14T22:13:20Z" {
		t.Fatalf("%+v %+v", am, am.Activity)
	}
}

func TestXray(t *testing.T) {
	s := mux(t, nil, map[string]string{
		"GET /xray/api/v1/system/ping":          `{"status":"pong"}`,
		"GET /xray/api/v1/binMgr/default/repos": `{"repos":[{"name":"docker-local"}]}`,
		"GET /xray/api/v1/policies":             `[{"name":"block-critical","type":"security"}]`,
		"GET /access/api/v1/tokens/me":          `{"last_used":0}`,
	})
	am := run(t, Xray, s, detectors.AccessCredential{Secret: "jf"})
	if !slices.Equal(resNames(am, "policy"), []string{"block-critical"}) || am.Activity != nil {
		t.Fatalf("%+v", am)
	}
}

func TestAuth0Exchange(t *testing.T) {
	s := mux(t, func(r *http.Request, body string) bool {
		if r.URL.Path == "/oauth/token" {
			var b map[string]string
			_ = json.Unmarshal([]byte(body), &b)
			return b["client_id"] == "cid" && b["client_secret"] == `se"c` && b["audience"] == "https://acme.auth0.com/api/v2/"
		}
		return r.Header.Get("Authorization") == "Bearer mgmt"
	}, map[string]string{
		"POST /oauth/token":            `{"access_token":"mgmt","scope":"read:users create:clients"}`,
		"GET /api/v2/clients":          `[{"name":"web","client_id":"c1"}]`,
		"GET /api/v2/resource-servers": `[{"identifier":"https://api.acme"}]`,
	})
	am := run(t, Auth0, s, detectors.AccessCredential{Secret: `se"c`, Extra: map[string]string{"client_id": "cid", "domain": "acme.auth0.com"}})
	if !am.Privileged || am.Identity.ID != "cid" || !slices.Equal(am.Permissions, []string{"read:users", "create:clients"}) || len(am.Resources) != 2 {
		t.Fatalf("%+v", am)
	}
	for _, d := range []string{"evil.com/path", "a@b.com", "x:8080", ""} {
		if _, err := (Mapper{Spec: Auth0}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "s", Extra: map[string]string{"domain": d}}); err == nil {
			t.Fatalf("domain %q must be refused", d)
		}
	}
}

func TestIBMCloud(t *testing.T) {
	s := mux(t, func(r *http.Request, body string) bool {
		if r.URL.Path == "/identity/token" {
			return strings.Contains(body, "apikey=ibm%2Bkey") && strings.Contains(body, "grant_type=urn%3Aibm")
		}
		return r.Header.Get("Authorization") == "Bearer iam" && r.Header.Get("IAM-Apikey") == "ibm+key"
	}, map[string]string{
		"POST /identity/token":                           `{"access_token":"iam"}`,
		"GET /v1/apikeys/details":                        `{"id":"ApiKey-1","name":"ci","account_id":"acct"}`,
		"GET /v2/resource_instances?limit=100":           `{"resources":[{"name":"cos"}],"next_url":"/v2/resource_instances?start=2"}`,
		"GET /v2/resource_instances?start=2":             `{"resources":[{"name":"db"}],"next_url":null}`,
		"GET /v1/apikeys/ApiKey-1?include_activity=true": `{"activity":{"last_authn":"2024-05-01T10:00+0000"}}`,
	})
	am := run(t, IBMCloud, s, detectors.AccessCredential{Secret: "ibm+key"})
	if am.Identity.Account != "acct" || !slices.Equal(resNames(am, "resource_instance"), []string{"cos", "db"}) || am.Activity == nil || am.Activity.LastUsed != "2024-05-01T10:00:00Z" {
		t.Fatalf("%+v %+v", am, am.Activity)
	}
}

func TestMondayGraphQL(t *testing.T) {
	s := mux(t, func(r *http.Request, _ string) bool { return r.Header.Get("Authorization") == "mt" }, map[string]string{
		"POST /v2#me { id":    `{"data":{"me":{"id":"1","email":"m@x","is_admin":true,"account":{"slug":"acme"}}}}`,
		"POST /v2#teams":      `{"data":{"me":{"teams":[{"name":"ops"}]}}}`,
		"POST /v2#workspaces": `{"data":{"workspaces":[{"name":"Main","kind":"open"}]}}`,
		"POST /v2#boards":     `{"errors":[{"message":"Permission denied"}]}`,
	})
	am := run(t, Monday, s, detectors.AccessCredential{Secret: "mt"})
	if !am.Privileged || am.Identity.Account != "acme" || !slices.Equal(resNames(am, "workspace"), []string{"Main"}) || !slices.Equal(resNames(am, "team"), []string{"ops"}) {
		t.Fatalf("%+v", am)
	}
	if !strings.Contains(strings.Join(am.Limitations, "|"), "board: graphql error: Permission denied") {
		t.Fatalf("limitations %v", am.Limitations)
	}
}

func TestMondayIdentityGraphQLError(t *testing.T) {
	s := mux(t, nil, map[string]string{"POST /v2": `{"errors":[{"message":"Not Authenticated"}]}`})
	if _, err := (Mapper{Spec: Monday, BaseURL: s.URL}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "x"}); err == nil {
		t.Fatal("GraphQL errors on identity must fail the mapping")
	}
}

func TestWandb(t *testing.T) {
	s := mux(t, func(r *http.Request, _ string) bool { u, p, ok := r.BasicAuth(); return ok && u == "api" && p == "wk" }, map[string]string{
		"POST /graphql": `{"data":{"viewer":{"id":"V1","username":"me","admin":false,"teams":{"edges":[{"node":{"name":"ml"}}]}}}}`,
	})
	am := run(t, WeightsAndBiases, s, detectors.AccessCredential{Secret: "wk"})
	if am.Privileged || am.Identity.Name != "me" || !slices.Equal(resNames(am, "team"), []string{"ml"}) {
		t.Fatalf("%+v", am)
	}
}

func TestPayPal(t *testing.T) {
	s := mux(t, func(r *http.Request, body string) bool {
		if r.URL.Path == "/v1/oauth2/token" {
			u, p, _ := r.BasicAuth()
			return u == "cid" && p == "csec" && body == "grant_type=client_credentials"
		}
		return r.Header.Get("Authorization") == "Bearer pp"
	}, map[string]string{
		"POST /v1/oauth2/token":            `{"access_token":"pp","scope":"openid https://uri.paypal.com/services/payments/refund"}`,
		"GET /v1/identity/oauth2/userinfo": `{"user_id":"https://www.paypal.com/webapps/auth/identity/user/abc"}`,
	})
	am := run(t, PayPal, s, detectors.AccessCredential{Secret: "cid", Secondary: "csec"})
	if !am.Privileged || am.Identity.ID != "cid" || len(resNames(am, "merchant")) != 1 {
		t.Fatalf("%+v", am)
	}
}

func TestPlaid(t *testing.T) {
	s := mux(t, func(_ *http.Request, body string) bool {
		return strings.Contains(body, `"client_id":"cid"`) && strings.Contains(body, `"secret":"sec"`)
	}, map[string]string{"POST /institutions/get": `{"institutions":[{"name":"Chase"}],"request_id":"r"}`})
	am := run(t, Plaid, s, detectors.AccessCredential{Secret: "cid", Secondary: "sec"})
	if !am.Privileged || !slices.Equal(resNames(am, "institution"), []string{"Chase"}) {
		t.Fatalf("%+v", am)
	}
	sb := run(t, Plaid, s, detectors.AccessCredential{Secret: "cid", Secondary: "sec", Extra: map[string]string{"environment": "sandbox"}})
	if sb.Privileged {
		t.Fatal("sandbox credentials are not privileged")
	}
}

func TestSalesforce(t *testing.T) {
	var soql string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sf" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/services/oauth2/userinfo":
			_, _ = w.Write([]byte(`{"user_id":"005xx' OR Id!='","preferred_username":"a@acme","organization_id":"00D"}`))
		case "/services/data/v60.0/query":
			soql = r.URL.Query().Get("q")
			_, _ = w.Write([]byte(`{"records":[{"Name":"Admin","PermissionsModifyAllData":true,"PermissionsViewAllData":true}]}`))
		case "/services/data/v60.0/sobjects":
			_, _ = w.Write([]byte(`{"sobjects":[{"name":"Account"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	am := run(t, Salesforce, s, detectors.AccessCredential{Secret: "sf"})
	if !am.Privileged || am.Identity.Account != "00D" || !slices.Equal(resNames(am, "sobject"), []string{"Account"}) {
		t.Fatalf("%+v", am)
	}
	if !strings.Contains(soql, "AssigneeId='005xxORId'") {
		t.Fatalf("identity id must be sanitized before SOQL substitution: %q", soql)
	}
}

func TestActivityLinkAndNormalize(t *testing.T) {
	sp := TerraformCloud
	s := mux(t, nil, map[string]string{
		"GET /api/v2/account/details":            `{"data":{"id":"user-1","type":"users","attributes":{"username":"u"},"links":{"auth-token":"/api/v2/authentication-tokens/at-1"}}}`,
		"GET /api/v2/organizations":              `{"data":[]}`,
		"GET /api/v2/authentication-tokens/at-1": `{"data":{"attributes":{"last-used-at":"2024-01-02T03:04:05.123Z"}}}`,
	})
	am := run(t, sp, s, detectors.AccessCredential{Secret: "t"})
	if am.Activity == nil || am.Activity.LastUsed != "2024-01-02T03:04:05Z" {
		t.Fatalf("%+v %v", am.Activity, am.Limitations)
	}
	for _, bad := range []string{"https://evil/x", "//evil/x", "/a/../b"} {
		s2 := mux(t, nil, map[string]string{
			"GET /api/v2/account/details": `{"data":{"id":"u","links":{"auth-token":"` + bad + `"}}}`,
			"GET /api/v2/organizations":   `{"data":[]}`,
		})
		if am := run(t, sp, s2, detectors.AccessCredential{Secret: "t"}); am.Activity != nil {
			t.Fatalf("link %q must be ignored", bad)
		}
	}
}

func TestExpandEncodes(t *testing.T) {
	c := detectors.AccessCredential{Secret: `a"b`, Extra: map[string]string{"k": "x y"}}
	if got := Expand(`{"s":"{secret}","k":"{extra.k}"}`, c, "", jsonEnc); got != `{"s":"a\"b","k":"x y"}` {
		t.Fatal(got)
	}
	if got := Expand("/p/{secret}?q={id}", c, "a'b/c", queryEnc); got != "/p/a%22b?q=abc" {
		t.Fatal(got)
	}
}
