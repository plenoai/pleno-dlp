package datadog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyAPI = "0123456789abcdef0123456789abcdef"
const dummyAPP = "0123456789abcdef0123456789abcdef01234567"

func TestFromData_Pair(t *testing.T) {
	body := []byte("DD_API_KEY=" + dummyAPI + "\nDD_APP_KEY=" + dummyAPP)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyAPP {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_SingleAPIOnly(t *testing.T) {
	body := []byte("DD_API_KEY=" + dummyAPI)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("RawV2 should be empty: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("single-key match must not be verified")
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyAPI)
	if r == dummyAPI {
		t.Fatalf("redact didn't redact: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") != dummyAPI {
			t.Errorf("DD-API-KEY mismatch")
		}
		if r.Header.Get("DD-APPLICATION-KEY") != dummyAPP {
			t.Errorf("DD-APPLICATION-KEY mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAPI+":"+dummyAPP)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAPI+":"+dummyAPP)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyEnrichesNameAndOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/validate":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/api_key/" + dummyAPI:
			_, _ = w.Write([]byte(`{"api_key":{
			  "name":"production-monitor",
			  "created_by":"sre@example.com"
			}}`))
		case "/api/v1/org":
			_, _ = w.Write([]byte(`{"orgs":[
			  {"name":"Acme Corp Production","public_id":"abc12345"}
			]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte("DD_API_KEY=" + dummyAPI + "\nDD_APP_KEY=" + dummyAPP)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"dd_api_key_name":       "production-monitor",
		"dd_api_key_created_by": "sre@example.com",
		"dd_org_names":          "Acme Corp Production",
		"dd_org_public_id":      "abc12345",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
}

func TestFromData_VerifyTolerantOfEnrichmentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/validate":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte("DD_API_KEY=" + dummyAPI + "\nDD_APP_KEY=" + dummyAPP)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if !res[0].Verified {
		t.Fatalf("expected Verified=true even when enrichment endpoints 403")
	}
	if _, ok := res[0].ExtraData["dd_api_key_name"]; ok {
		t.Errorf("dd_api_key_name must be absent on enrichment 403")
	}
	if _, ok := res[0].ExtraData["dd_org_names"]; ok {
		t.Errorf("dd_org_names must be absent on enrichment 403")
	}
}

func TestFromData_VerifyMultipleOrgsJoined(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/validate":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/api_key/" + dummyAPI:
			w.WriteHeader(http.StatusForbidden)
		case "/api/v1/org":
			_, _ = w.Write([]byte(`{"orgs":[
			  {"name":"Zeta Sub","public_id":"z1"},
			  {"name":"Acme Parent","public_id":"a1"}
			]}`))
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte("DD_API_KEY=" + dummyAPI + "\nDD_APP_KEY=" + dummyAPP)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if res[0].ExtraData["dd_org_names"] != "Acme Parent,Zeta Sub" {
		t.Errorf("dd_org_names = %q, want sorted csv", res[0].ExtraData["dd_org_names"])
	}
}
