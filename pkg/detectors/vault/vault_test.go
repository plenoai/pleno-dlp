package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyHvs = "hvs.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
const dummyLegacy = "s.AbCdEfGhIjKlMnOpQrStUvWx"

func TestFromData_Modern(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("VAULT_TOKEN="+dummyHvs))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Vault is unverified-by-design (server URL unknown); got Verified=true")
	}
	if string(res[0].Raw) != dummyHvs {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Legacy(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("VAULT_TOKEN="+dummyLegacy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyLegacy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("hvs.short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// withAPIBase points apiBase at srv and restores it afterwards.
func withAPIBase(t *testing.T, url string) {
	t.Helper()
	prev := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = prev })
}

func newVaultServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != dummyHvs {
			t.Errorf("missing/incorrect X-Vault-Token header: %q", r.Header.Get("X-Vault-Token"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("must not use Bearer/Authorization; got %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerify_NoAPIBase_NoOp(t *testing.T) {
	// Default apiBase is empty: Verify must not probe and must return false,nil.
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if v || err != nil {
		t.Fatalf("expected no-op (false,nil), got verified=%v err=%v", v, err)
	}
}

func TestVerify_Accept200(t *testing.T) {
	srv := newVaultServer(t, http.StatusOK)
	withAPIBase(t, srv.URL)
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Reject403(t *testing.T) {
	srv := newVaultServer(t, http.StatusForbidden)
	withAPIBase(t, srv.URL)
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if v {
		t.Fatal("expected verified=false on 403")
	}
	if err != nil {
		t.Fatalf("403 is an authoritative rejection, want nil err; got %v", err)
	}
}

func TestVerify_Reject401(t *testing.T) {
	srv := newVaultServer(t, http.StatusUnauthorized)
	withAPIBase(t, srv.URL)
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if v || err != nil {
		t.Fatalf("expected (false,nil) on 401; got verified=%v err=%v", v, err)
	}
}

func TestVerify_Transient500(t *testing.T) {
	srv := newVaultServer(t, http.StatusInternalServerError)
	withAPIBase(t, srv.URL)
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if v {
		t.Fatal("expected verified=false on 500")
	}
	if err == nil {
		t.Fatal("500 is transient, want non-nil err")
	}
}

func TestVerify_Transient429(t *testing.T) {
	srv := newVaultServer(t, http.StatusTooManyRequests)
	withAPIBase(t, srv.URL)
	v, err := Scanner{}.Verify(context.Background(), dummyHvs)
	if v {
		t.Fatal("expected verified=false on 429")
	}
	if err == nil {
		t.Fatal("429 is transient, want non-nil err")
	}
}

func TestFromData_VerifiesWhenAPIBaseSet(t *testing.T) {
	srv := newVaultServer(t, http.StatusOK)
	withAPIBase(t, srv.URL)
	res, err := Scanner{}.FromData(context.Background(), true, []byte("VAULT_TOKEN="+dummyHvs))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true when apiBase override returns 200")
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyHvs)
	if r == dummyHvs {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "hvs.Ab") {
		t.Fatalf("missing prefix: %q", r)
	}
}
