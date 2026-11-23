//go:build detector_unit

package anthropic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const leaked = "sk-ant-api03-leaked"

func setup(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	t.Setenv(EnvRevokeAdminKey, "sk-ant-admin01-x")
	t.Setenv(EnvRevokeKeyID, "apikey_01")
}

func TestRevoke_DeactivatesExactKey(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/organizations/api_keys/apikey_01" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "sk-ant-admin01-x" {
			t.Errorf("admin key not sent")
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"inactive"`) || strings.Contains(string(b), leaked) {
			t.Errorf("body = %s", b)
		}
		_, _ = w.Write([]byte(`{"type":"api_key","id":"apikey_01","status":"inactive"}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), leaked)
	if err != nil || !res.Revoked || res.ProviderID != "apikey_01" || res.RevokedAt.IsZero() {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_UnconfirmedResponse(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"api_key","id":"other","status":"inactive"}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), leaked)
	if err != nil || res.Revoked || res.Err == nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_HardErrors(t *testing.T) {
	for _, code := range []int{401, 404, 429, 500} {
		setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		if _, err := (Scanner{}).Revoke(context.Background(), leaked); err == nil {
			t.Errorf("HTTP %d: want error", code)
		}
	}
}

func TestRevoke_RequiresContext(t *testing.T) {
	t.Setenv(EnvRevokeAdminKey, "")
	t.Setenv(EnvRevokeKeyID, "")
	if _, err := (Scanner{}).Revoke(context.Background(), leaked); err == nil || !strings.Contains(err.Error(), EnvRevokeKeyID) {
		t.Fatalf("err = %v", err)
	}
	if _, err := (Scanner{}).Revoke(context.Background(), ""); err == nil {
		t.Fatal("empty secret must error")
	}
	if _, err := (Scanner{}).Revoke(context.Background(), "sk-ant-admin01-zzz"); err == nil {
		t.Fatal("admin key must be rejected")
	}
}
