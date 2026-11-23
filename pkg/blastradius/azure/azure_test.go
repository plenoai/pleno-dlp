package azure

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func fakeJWT(roles string) string {
	return "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"roles":`+roles+`}`)) + ".s"
}

func TestServicePrincipal(t *testing.T) {
	graphTok, armTok := fakeJWT(`["User.Read.All","Application.ReadWrite.All"]`), fakeJWT(`[]`)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tid/oauth2/v2.0/token":
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "sec" || r.Form.Get("client_id") != "cid" {
				w.WriteHeader(401)
				return
			}
			tok := graphTok
			if strings.Contains(r.Form.Get("scope"), "management") {
				tok = armTok
			}
			_, _ = w.Write([]byte(`{"access_token":"` + tok + `"}`))
		case r.URL.Path == "/v1.0/servicePrincipals(appId='cid')":
			_, _ = w.Write([]byte(`{"id":"sp1","displayName":"ci-bot"}`))
		case r.URL.Path == "/v1.0/servicePrincipals/sp1/memberOf":
			_, _ = w.Write([]byte(`{"value":[{"@odata.type":"#microsoft.graph.directoryRole","displayName":"Directory Readers"}]}`))
		case r.URL.Path == "/subscriptions":
			_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"s1","displayName":"prod"}]}`))
		case r.URL.Path == "/subscriptions/s1/providers/Microsoft.Authorization/roleAssignments":
			if r.Header.Get("Authorization") != "Bearer "+armTok || r.URL.Query().Get("$filter") != "assignedTo('sp1')" {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"value":[{"properties":{"roleDefinitionId":"/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/r1","scope":"/subscriptions/s1"}},{"properties":{"roleDefinitionId":"/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/r2","scope":"/subscriptions/s1/resourceGroups/rg"}}]}`))
		case strings.HasSuffix(r.URL.Path, "/roleDefinitions/r1"):
			_, _ = w.Write([]byte(`{"properties":{"roleName":"Reader"}}`))
		case strings.HasSuffix(r.URL.Path, "/roleDefinitions/r2"):
			_, _ = w.Write([]byte(`{"properties":{"roleName":"Contributor"}}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	m := ServicePrincipalMapper{LoginURL: s.URL, GraphURL: s.URL, ARMURL: s.URL}
	am, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: "sec", Extra: map[string]string{"tenant_id": "tid", "client_id": "cid"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"graph:User.Read.All", "graph:Application.ReadWrite.All", "rbac:Reader", "rbac:Contributor@/subscriptions/s1/resourceGroups/rg"}
	if !slices.Equal(am.Permissions, want) || !am.Privileged || am.Identity.Name != "ci-bot" {
		t.Fatalf("%+v", am)
	}
	if _, err := m.MapAccess(context.Background(), detectors.AccessCredential{Secret: "x"}); err == nil {
		t.Fatal("missing tenant must fail")
	}
}

func TestStorageKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want, _ := http.NewRequest(http.MethodGet, "http://x"+r.URL.RequestURI(), nil)
		sign(want, "acct", []byte("0123456789abcdef"), now)
		if r.Header.Get("Authorization") != want.Header.Get("Authorization") || !strings.HasPrefix(r.Header.Get("Authorization"), "SharedKey acct:") {
			w.WriteHeader(403)
			return
		}
		if r.URL.Query().Get("marker") == "" {
			_, _ = w.Write([]byte(`<EnumerationResults><Containers><Container><Name>logs</Name></Container></Containers><NextMarker>n2</NextMarker></EnumerationResults>`))
			return
		}
		_, _ = w.Write([]byte(`<EnumerationResults><Containers><Container><Name>backups</Name></Container></Containers><NextMarker/></EnumerationResults>`))
	}))
	defer s.Close()
	am, err := StorageKeyMapper{BaseURL: s.URL, Now: func() time.Time { return now }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: key, Extra: map[string]string{"account": "acct"}})
	if err != nil {
		t.Fatal(err)
	}
	if !am.Privileged || len(am.Resources) != 2 || am.Resources[1].Name != "backups" {
		t.Fatalf("%+v", am)
	}
	// Known-answer check of the canonical string-to-sign shape.
	req, _ := http.NewRequest(http.MethodGet, "https://acct.blob.core.windows.net/?comp=list", nil)
	sign(req, "acct", []byte("k"), now)
	if req.Header.Get("x-ms-date") != "Tue, 24 Nov 2026 00:00:00 GMT" {
		t.Fatalf("date %q", req.Header.Get("x-ms-date"))
	}
}
