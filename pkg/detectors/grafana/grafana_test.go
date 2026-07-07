//go:build detector_unit

package grafana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "glsa_AbCdEfGhIjKlMnOpQrStUvWxYz012345_0a1b2c3d"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("GRAFANA_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Grafana must stay unverified when no apiBase override is set")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("glsa_short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "glsa_AbC") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func setAPIBase(t *testing.T, url string) {
	t.Helper()
	prev := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = prev })
}

func TestVerify_NoApiBase(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected unverified when apiBase is empty")
	}
}

func TestVerify_Accept200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummy {
			t.Errorf("unexpected auth header %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"admin"}`))
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_FromData_Accept200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	res, err := Scanner{}.FromData(context.Background(), true, []byte("GRAFANA_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected verified=true via FromData on 200")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected verification err: %v", res[0].VerificationErr)
	}
}

func TestVerify_Reject(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: expected no error on explicit rejection, got %v", code, err)
		}
		if v {
			t.Fatalf("code %d: expected verified=false on rejection", code)
		}
	}
}

func TestVerify_Transient(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if err == nil {
			t.Fatalf("code %d: expected transient error", code)
		}
		if v {
			t.Fatalf("code %d: expected verified=false on transient", code)
		}
	}
}
