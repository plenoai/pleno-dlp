//go:build detector_unit

package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyToken = "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("token leaked: "+dummyToken))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyToken {
		t.Errorf("Raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("xoxa-not-bot 12345"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"team":"T1"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_NotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on ok=false")
	}
}

func TestFromData_VerifyEnrichesIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "chat:write, files:write, users:read")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "ok": true,
		  "url": "https://acme.slack.com/",
		  "team": "Acme Corp",
		  "user": "deploybot",
		  "team_id": "T0123456789",
		  "user_id": "U0123456789",
		  "bot_id": "B0123456789",
		  "is_enterprise_install": false
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, err := Scanner{}.FromData(context.Background(), true, []byte(dummyToken))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if !res[0].Verified {
		t.Errorf("expected Verified=true")
	}
	want := map[string]string{
		"slack_team_id":   "T0123456789",
		"slack_team_name": "Acme Corp",
		"slack_team_url":  "https://acme.slack.com/",
		"slack_user_id":   "U0123456789",
		"slack_user_name": "deploybot",
		"slack_bot_id":    "B0123456789",
		"slack_scopes":    "chat:write,files:write,users:read",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	if res[0].ExtraData["slack_privileged"] != "true" {
		t.Errorf("files:write should flag privileged, got %v", res[0].ExtraData)
	}
	if _, ok := res[0].ExtraData["slack_enterprise_install"]; ok {
		t.Errorf("enterprise_install must not be present when false")
	}
}

func TestFromData_VerifyEnterpriseFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "ok": true,
		  "team_id": "T1",
		  "enterprise_id": "E0123456789",
		  "is_enterprise_install": true
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyToken))
	if res[0].ExtraData["slack_enterprise_id"] != "E0123456789" {
		t.Errorf("enterprise_id missing: %v", res[0].ExtraData)
	}
	if res[0].ExtraData["slack_enterprise_install"] != "true" {
		t.Errorf("enterprise_install flag missing")
	}
}

func TestFromData_VerifyNonPrivilegedScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "channels:read,users:read")
		_, _ = w.Write([]byte(`{"ok":true,"team_id":"T1"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyToken))
	if _, ok := res[0].ExtraData["slack_privileged"]; ok {
		t.Errorf("read-only scopes must not flip privileged: %v", res[0].ExtraData)
	}
}

func TestFromData_VerifyOKNoMetaOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyToken))
	if res[0].Verified {
		t.Errorf("Verified must be false")
	}
	if res[0].ExtraData["slack_team_id"] != "" {
		t.Errorf("metadata must be absent on ok=false: %v", res[0].ExtraData)
	}
}

func TestHasPrivilegedScope(t *testing.T) {
	cases := map[string]bool{
		"admin":                          true,
		"chat:write,users:read":          false,
		"chat:write.public":              true,
		"users:read.email,channels:read": true,
		"":                               false,
	}
	for in, want := range cases {
		if got := hasPrivilegedScope(in); got != want {
			t.Errorf("hasPrivilegedScope(%q) = %v, want %v", in, got, want)
		}
	}
}
