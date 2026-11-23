//go:build detector_unit

package notion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const tok = "notion-oauth-test-token"

func setup(t *testing.T, introspect []string, revokeCode int) *atomic.Int32 {
	t.Helper()
	var calls, revokes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "cid" || p != "csec" {
			t.Errorf("basic auth missing")
		}
		switch r.URL.Path {
		case "/v1/oauth/introspect":
			i := int(calls.Add(1)) - 1
			_, _ = w.Write([]byte(introspect[i]))
		case "/v1/oauth/revoke":
			revokes.Add(1)
			w.WriteHeader(revokeCode)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	t.Setenv(EnvRevokeClientID, "cid")
	t.Setenv(EnvRevokeClientSecret, "csec")
	return &revokes
}

func TestRevoke_IntrospectRevokeIntrospect(t *testing.T) {
	revokes := setup(t, []string{`{"active":true}`, `{"active":false}`}, 200)
	res, err := Scanner{}.Revoke(context.Background(), tok)
	if err != nil || !res.Revoked || res.Err != nil || revokes.Load() != 1 {
		t.Fatalf("res=%+v err=%v revokes=%d", res, err, revokes.Load())
	}
}

func TestRevoke_AlreadyInactiveSkipsRevoke(t *testing.T) {
	revokes := setup(t, []string{`{"active":false}`}, 200)
	res, err := Scanner{}.Revoke(context.Background(), tok)
	if err != nil || !res.Revoked || res.Err == nil || revokes.Load() != 0 {
		t.Fatalf("res=%+v err=%v revokes=%d", res, err, revokes.Load())
	}
}

func TestRevoke_StillActiveIsUnconfirmed(t *testing.T) {
	setup(t, []string{`{"active":true}`, `{"active":true}`}, 200)
	res, err := Scanner{}.Revoke(context.Background(), tok)
	if err != nil || res.Revoked || res.Err == nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_Errors(t *testing.T) {
	setup(t, []string{`{"active":true}`}, 500)
	if _, err := (Scanner{}).Revoke(context.Background(), tok); err == nil {
		t.Error("revoke 500 must error")
	}
	setup(t, []string{`{}`}, 200)
	if _, err := (Scanner{}).Revoke(context.Background(), tok); err == nil {
		t.Error("introspect without active must error")
	}
	t.Setenv(EnvRevokeClientID, "")
	if _, err := (Scanner{}).Revoke(context.Background(), tok); err == nil {
		t.Error("missing client id must error")
	}
}
