//go:build detector_unit

package resend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const keyID = "0b5e2e6c-1d2a-4f7e-9a3b-123456789abc"

func setup(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	t.Setenv(EnvRevokeAdminKey, "re_admin")
	t.Setenv(EnvRevokeKeyID, keyID)
}

func TestRevoke_DeletesKey(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api-keys/"+keyID || r.Header.Get("Authorization") != "Bearer re_admin" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"api_key","id":"` + keyID + `","deleted":true}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), "re_leaked_value")
	if err != nil || !res.Revoked || res.ProviderID != keyID {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_Outcomes(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"api_key","id":"x","deleted":true}`))
	})
	if res, err := (Scanner{}).Revoke(context.Background(), "re_x"); err != nil || res.Revoked {
		t.Errorf("id mismatch must be unconfirmed: %+v %v", res, err)
	}
	setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if res, err := (Scanner{}).Revoke(context.Background(), "re_x"); err != nil || !res.Revoked || res.Err == nil {
		t.Errorf("404 idempotent: %+v %v", res, err)
	}
	setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	if _, err := (Scanner{}).Revoke(context.Background(), "re_x"); err == nil {
		t.Error("403 must error")
	}
	t.Setenv(EnvRevokeKeyID, "not-a-uuid")
	if _, err := (Scanner{}).Revoke(context.Background(), "re_x"); err == nil {
		t.Error("non-UUID id must error")
	}
	t.Setenv(EnvRevokeAdminKey, "")
	if _, err := (Scanner{}).Revoke(context.Background(), "re_x"); err == nil {
		t.Error("missing admin key must error")
	}
}
