package heroku

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "01234567-89ab-cdef-0123-456789abcdef"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("HEROKU_API_KEY="+dummy))
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

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// UUID alone, no heroku keyword in the window → must skip.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("uuid="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	// Misshapen UUID near keyword.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("heroku=not-a-uuid"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch")
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.heroku+json") {
			t.Errorf("missing heroku accept header: %q", r.Header.Get("Accept"))
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

func TestFromData_VerifyHighRiskNo2FA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			t.Errorf("expected /account, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
		  "id":"acc-uuid","email":"alice@example.com","name":"Alice",
		  "two_factor_authentication":false,
		  "sso_target_url":null,"federated":false,
		  "suspended_at":null,"verified":true
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("HEROKU_API_KEY="+dummy))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"heroku_user_id":    "acc-uuid",
		"heroku_email":      "alice@example.com",
		"heroku_user_name":  "Alice",
		"heroku_two_factor": "false",
		"heroku_high_risk":  "true",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	for _, off := range []string{"heroku_sso", "heroku_account_suspended"} {
		if _, ok := res[0].ExtraData[off]; ok {
			t.Errorf("%s must be absent", off)
		}
	}
}

func TestFromData_Verify2FANotHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "id":"x","email":"e","name":"n",
		  "two_factor_authentication":true,
		  "sso_target_url":null,"federated":false,
		  "suspended_at":null
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("heroku="+dummy))
	if res[0].ExtraData["heroku_two_factor"] != "true" {
		t.Errorf("heroku_two_factor = %q, want true", res[0].ExtraData["heroku_two_factor"])
	}
	if _, ok := res[0].ExtraData["heroku_high_risk"]; ok {
		t.Errorf("2FA-on account must not be high_risk")
	}
}

func TestFromData_VerifySSOFederated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "id":"x","email":"e","name":"n",
		  "two_factor_authentication":false,
		  "sso_target_url":"https://idp.example.com/saml",
		  "federated":true,
		  "suspended_at":null
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("heroku="+dummy))
	if res[0].ExtraData["heroku_sso"] != "true" {
		t.Errorf("expected heroku_sso=true")
	}
	if _, ok := res[0].ExtraData["heroku_high_risk"]; ok {
		t.Errorf("SSO-gated account must not be marked high_risk even without 2FA")
	}
}

func TestFromData_VerifySuspended(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "id":"x","email":"e","name":"n",
		  "two_factor_authentication":false,
		  "sso_target_url":null,"federated":false,
		  "suspended_at":"2024-01-01T00:00:00Z"
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("heroku="+dummy))
	if res[0].ExtraData["heroku_account_suspended"] != "true" {
		t.Errorf("expected heroku_account_suspended=true")
	}
	if _, ok := res[0].ExtraData["heroku_high_risk"]; ok {
		t.Errorf("suspended account must not be marked high_risk")
	}
}
