package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 36 base62 chars after "npm_".
const dummyTok = "npm_abcdefghijklmnopqrstuvwxyz0123456789"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("//registry.npmjs.org/:_authToken="+dummyTok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("npm_short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyTok)
	if !strings.HasPrefix(r, "npm_") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyTok {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyTok)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyTok)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyEnrichesIdentityAndTFAStrong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			_, _ = w.Write([]byte(`{"username":"alice"}`))
		case "/-/npm/v1/user":
			_, _ = w.Write([]byte(`{
			  "name":"alice","email":"alice@example.com",
			  "tfa":{"mode":"auth-and-writes","pending":false}
			}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyTok))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"npm_username":             "alice",
		"npm_email":                "alice@example.com",
		"npm_full_name":            "alice",
		"npm_tfa_mode":             "auth-and-writes",
		"npm_publish_requires_tfa": "true",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	if _, ok := res[0].ExtraData["npm_high_risk"]; ok {
		t.Errorf("auth-and-writes must not be marked high_risk")
	}
}

func TestFromData_VerifyTFAAuthOnlyMarkedHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			_, _ = w.Write([]byte(`{"username":"bob"}`))
		case "/-/npm/v1/user":
			_, _ = w.Write([]byte(`{"name":"bob","tfa":{"mode":"auth-only"}}`))
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyTok))
	if res[0].ExtraData["npm_tfa_mode"] != "auth-only" {
		t.Errorf("npm_tfa_mode = %q, want auth-only", res[0].ExtraData["npm_tfa_mode"])
	}
	if res[0].ExtraData["npm_high_risk"] != "true" {
		t.Errorf("auth-only must be marked npm_high_risk=true")
	}
	if _, ok := res[0].ExtraData["npm_publish_requires_tfa"]; ok {
		t.Errorf("auth-only must NOT carry npm_publish_requires_tfa")
	}
}

func TestFromData_VerifyTFAFalseDisabledHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			_, _ = w.Write([]byte(`{"username":"carol"}`))
		case "/-/npm/v1/user":
			_, _ = w.Write([]byte(`{"name":"carol","tfa":false}`))
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyTok))
	if res[0].ExtraData["npm_tfa_mode"] != "disabled" {
		t.Errorf("npm_tfa_mode = %q, want disabled", res[0].ExtraData["npm_tfa_mode"])
	}
	if res[0].ExtraData["npm_high_risk"] != "true" {
		t.Errorf("disabled TFA must be npm_high_risk=true")
	}
}

func TestFromData_VerifyProfileFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			_, _ = w.Write([]byte(`{"username":"dave"}`))
		case "/-/npm/v1/user":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyTok))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true even when profile fetch fails")
	}
	if res[0].ExtraData["npm_username"] != "dave" {
		t.Errorf("npm_username = %q, want dave", res[0].ExtraData["npm_username"])
	}
	if _, ok := res[0].ExtraData["npm_tfa_mode"]; ok {
		t.Errorf("npm_tfa_mode must be absent when profile fetch fails")
	}
}

func TestTFAMode(t *testing.T) {
	cases := map[string]string{
		`{"mode":"auth-and-writes"}`: "auth-and-writes",
		`{"mode":"auth-only"}`:       "auth-only",
		`false`:                      "disabled",
		`null`:                       "disabled",
		`{}`:                         "disabled",
		``:                           "disabled",
	}
	for in, want := range cases {
		got := tfaMode([]byte(in))
		if got != want {
			t.Errorf("tfaMode(%q) = %q, want %q", in, got, want)
		}
	}
}
