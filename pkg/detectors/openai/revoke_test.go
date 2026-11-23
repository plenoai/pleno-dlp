//go:build detector_unit

package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setup(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	t.Setenv(EnvRevokeAdminKey, "sk-admin-mgmt")
	t.Setenv(EnvRevokeProjectID, "proj_1")
	t.Setenv(EnvRevokeKeyID, "key_1")
}

func TestRevoke_ProjectKey(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/organization/projects/proj_1/api_keys/key_1" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-admin-mgmt" {
			t.Errorf("admin auth missing")
		}
		_, _ = w.Write([]byte(`{"object":"organization.project.api_key.deleted","id":"key_1","deleted":true}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), "sk-proj-leaked")
	if err != nil || !res.Revoked || res.ProviderID != "key_1" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_AdminKeyEndpoint(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/organization/admin_api_keys/key_1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"organization.admin_api_key.deleted","id":"key_1","deleted":true}`))
	})
	t.Setenv(EnvRevokeProjectID, "")
	res, err := Scanner{}.Revoke(context.Background(), "sk-admin-leaked")
	if err != nil || !res.Revoked {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_WrongObjectIsUnconfirmed(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"organization.project.service_account.deleted","id":"key_1","deleted":true}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), "sk-proj-leaked")
	if err != nil || res.Revoked || res.Err == nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_NotFoundIdempotent(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	res, err := Scanner{}.Revoke(context.Background(), "sk-proj-leaked")
	if err != nil || !res.Revoked || res.Err == nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_HardErrors(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	if _, err := (Scanner{}).Revoke(context.Background(), "sk-proj-leaked"); err == nil {
		t.Fatal("401 must error")
	}
	t.Setenv(EnvRevokeProjectID, "")
	if _, err := (Scanner{}).Revoke(context.Background(), "sk-proj-leaked"); err == nil || !strings.Contains(err.Error(), EnvRevokeProjectID) {
		t.Fatalf("missing project: %v", err)
	}
	t.Setenv(EnvRevokeAdminKey, "")
	if _, err := (Scanner{}).Revoke(context.Background(), "sk-proj-leaked"); err == nil {
		t.Fatal("missing admin key must error")
	}
}
