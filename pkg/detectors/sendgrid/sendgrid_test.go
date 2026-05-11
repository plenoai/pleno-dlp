package sendgrid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 22 chars id, 43 chars secret.
const dummyKey = "SG.aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefg"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("SENDGRID="+dummyKey))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("SG.short.short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyKey)
	if !strings.HasPrefix(r, "SG.") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyKey {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
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

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyFullAccessKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/scopes" {
			t.Errorf("expected /v3/scopes, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"scopes":[
		  "mail.send","api_keys.create","api_keys.update","api_keys.delete",
		  "billing.read","billing.update","user.account.update",
		  "user.email.update","stats.read","subusers.create"
		]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	if res[0].ExtraData["sendgrid_key_kind"] != "full-access" {
		t.Errorf("sendgrid_key_kind = %q, want full-access", res[0].ExtraData["sendgrid_key_kind"])
	}
	if res[0].ExtraData["sendgrid_privileged"] != "true" {
		t.Errorf("expected sendgrid_privileged=true")
	}
	scopes := res[0].ExtraData["sendgrid_scopes"]
	if !strings.Contains(scopes, "mail.send") {
		t.Errorf("scopes csv missing mail.send: %q", scopes)
	}
	priv := res[0].ExtraData["sendgrid_privileged_scopes"]
	for _, must := range []string{"mail.send", "api_keys.create", "billing.update", "subusers.create"} {
		if !strings.Contains(priv, must) {
			t.Errorf("sendgrid_privileged_scopes %q missing %q", priv, must)
		}
	}
}

func TestFromData_VerifyRestrictedReadOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scopes":["stats.read","categories.read"]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	if res[0].ExtraData["sendgrid_key_kind"] != "restricted" {
		t.Errorf("sendgrid_key_kind = %q, want restricted", res[0].ExtraData["sendgrid_key_kind"])
	}
	if _, ok := res[0].ExtraData["sendgrid_privileged"]; ok {
		t.Errorf("read-only key must not be marked privileged")
	}
}

func TestFromData_VerifyRestrictedWithMailSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scopes":["mail.send","stats.read"]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if res[0].ExtraData["sendgrid_key_kind"] != "restricted" {
		t.Errorf("sendgrid_key_kind = %q, want restricted", res[0].ExtraData["sendgrid_key_kind"])
	}
	if res[0].ExtraData["sendgrid_privileged"] != "true" {
		t.Errorf("a key with mail.send must be privileged even when restricted")
	}
}

func TestFromData_VerifyEmptyScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scopes":[]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true on 200 with empty scopes")
	}
	if res[0].ExtraData["sendgrid_key_kind"] != "billing-or-empty" {
		t.Errorf("sendgrid_key_kind = %q, want billing-or-empty", res[0].ExtraData["sendgrid_key_kind"])
	}
}

func TestPrivilegedHits(t *testing.T) {
	hits := privilegedHits([]string{"mail.send", "stats.read", "subusers.create", "categories.read"})
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d (%v)", len(hits), hits)
	}
	want := map[string]bool{"mail.send": true, "subusers.create": true}
	for _, h := range hits {
		if !want[h] {
			t.Errorf("unexpected hit %q", h)
		}
	}
}

func TestHasAll(t *testing.T) {
	if !hasAll([]string{"a", "b", "c"}, "a", "c") {
		t.Error("expected true")
	}
	if hasAll([]string{"a", "b"}, "a", "z") {
		t.Error("expected false")
	}
}
