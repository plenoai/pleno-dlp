package pagerduty

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummy = "u_NbAkKc66ryYTWUXYEu" // 20 chars [A-Za-z0-9_-]

func TestFromData_Positive_WithKeyword(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("PD_API_KEY="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative_NoKeyword(t *testing.T) {
	// 20-char shape, but no PagerDuty context keyword nearby — must skip.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative_TooShort(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("pagerduty key=short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token token="+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") == "" {
			t.Errorf("missing Accept header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
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

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyUserScopedAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/me" {
			t.Errorf("expected /users/me, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"user":{
		  "id":"P12345","name":"Alice Operator",
		  "email":"alice@example.com","role":"admin"
		}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("PD_API_KEY="+dummy))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"pd_token_kind": "user",
		"pd_user_id":    "P12345",
		"pd_user_name":  "Alice Operator",
		"pd_user_email": "alice@example.com",
		"pd_user_role":  "admin",
		"pd_privileged": "true",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
}

func TestFromData_VerifyUserScopedReadOnlyNotPrivileged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"user":{"id":"P9","name":"Bob","email":"b@x","role":"observer"}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("PD_API_KEY="+dummy))
	if res[0].ExtraData["pd_user_role"] != "observer" {
		t.Errorf("pd_user_role = %q, want observer", res[0].ExtraData["pd_user_role"])
	}
	if _, ok := res[0].ExtraData["pd_privileged"]; ok {
		t.Errorf("observer must not be marked privileged")
	}
}

func TestFromData_VerifyGeneralAccessFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/me":
			// General Access tokens 404 here (no associated user).
			w.WriteHeader(http.StatusNotFound)
		case "/users":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("PD_API_KEY="+dummy))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true via /users fallback")
	}
	if res[0].ExtraData["pd_token_kind"] != "general-access" {
		t.Errorf("pd_token_kind = %q, want general-access", res[0].ExtraData["pd_token_kind"])
	}
	if res[0].ExtraData["pd_privileged"] != "true" {
		t.Errorf("general-access tokens must be marked privileged")
	}
}

func TestFromData_VerifyForbiddenStopsImmediately(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("PD_API_KEY="+dummy))
	if res[0].Verified {
		t.Errorf("expected verified=false on 403")
	}
	if calls != 1 {
		t.Errorf("403 must short-circuit, but server saw %d calls (expected 1)", calls)
	}
}
