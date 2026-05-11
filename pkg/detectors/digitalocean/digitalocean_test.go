package digitalocean

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "dop_v1_" + // 7 chars prefix
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("DO_TOKEN="+dummy))
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

func TestFromData_Negative(t *testing.T) {
	// Wrong prefix and too short: must not match.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("dop_v2_aaaa"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if !strings.HasPrefix(r, "dop_v1_") {
		t.Fatalf("missing prefix: %q", r)
	}
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
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

func TestFromData_VerifyEnrichesActiveVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/account" {
			t.Errorf("expected /v2/account, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"account":{
		  "email":"alice@example.com","uuid":"u-123",
		  "email_verified":true,"status":"active",
		  "droplet_limit":50,"floating_ip_limit":5,
		  "team":{"uuid":"t-1","name":"Acme Engineering"}
		}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummy))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"do_email":             "alice@example.com",
		"do_user_uuid":         "u-123",
		"do_status":            "active",
		"do_email_verified":    "true",
		"do_droplet_limit":     "50",
		"do_floating_ip_limit": "5",
		"do_team_name":         "Acme Engineering",
		"do_team_uuid":         "t-1",
		"do_high_risk":         "true",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
}

func TestFromData_VerifyLockedNotHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"account":{
		  "email":"x","status":"locked","email_verified":true,
		  "droplet_limit":25
		}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummy))
	if res[0].ExtraData["do_account_locked"] != "true" {
		t.Errorf("expected do_account_locked=true")
	}
	if _, ok := res[0].ExtraData["do_high_risk"]; ok {
		t.Errorf("locked account must not be marked high_risk")
	}
}

func TestFromData_VerifyUnverifiedEmailNotHighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"account":{
		  "email":"x","status":"active","email_verified":false,
		  "droplet_limit":25
		}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummy))
	if res[0].ExtraData["do_email_verified"] != "false" {
		t.Errorf("do_email_verified = %q, want false", res[0].ExtraData["do_email_verified"])
	}
	if _, ok := res[0].ExtraData["do_high_risk"]; ok {
		t.Errorf("unverified-email account must not be marked high_risk")
	}
}
