//go:build detector_unit

package mailgun

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	dummyLegacy = "key-0123456789abcdef0123456789abcdef"
	dummyNew    = "0123456789abcdef0123456789abcdef-01234567-89abcdef"
)

func TestFromData_Legacy(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("MAILGUN_API_KEY="+dummyLegacy))
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

func TestFromData_New(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("MAILGUN_KEY="+dummyNew))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key-too-short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyLegacy)
	if r == dummyLegacy {
		t.Fatal("redact didn't redact")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("api:"+dummyLegacy))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLegacy)
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

	v, err := Scanner{}.Verify(context.Background(), dummyLegacy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
