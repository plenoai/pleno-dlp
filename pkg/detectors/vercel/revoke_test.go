//go:build detector_unit

package vercel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setup(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestRevoke_SelfDelete(t *testing.T) {
	const tok = "abcdefghijklmnopqrstuvwx"
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v3/user/tokens/current" || r.Header.Get("Authorization") != "Bearer "+tok {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"tokenId":"t1"}`))
	})
	res, err := Scanner{}.Revoke(context.Background(), tok)
	if err != nil || !res.Revoked || res.Err != nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_Outcomes(t *testing.T) {
	for code, want := range map[int]string{204: "ok", 401: "idem", 403: "idem", 429: "err", 500: "err"} {
		setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		res, err := Scanner{}.Revoke(context.Background(), "abcdefghijklmnopqrstuvwx")
		switch want {
		case "ok":
			if err != nil || !res.Revoked || res.Err != nil {
				t.Errorf("%d: %+v %v", code, res, err)
			}
		case "idem":
			if err != nil || !res.Revoked || res.Err == nil {
				t.Errorf("%d: %+v %v", code, res, err)
			}
		default:
			if err == nil {
				t.Errorf("%d: want error", code)
			}
		}
	}
}
