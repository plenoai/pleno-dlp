//go:build detector_unit

package airtable

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyPAT = "patABCDEF12345678.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const dummyLegacy = "keyABCDEF12345678"

func TestFromData_PAT(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("AIRTABLE_TOKEN="+dummyPAT))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyPAT {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Legacy_KeywordRequired(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyLegacy))
	if len(res) != 0 {
		t.Fatalf("legacy without keyword should not match, got %d", len(res))
	}
	res, _ = Scanner{}.FromData(context.Background(), false, []byte("AIRTABLE_API_KEY="+dummyLegacy))
	if len(res) != 1 {
		t.Fatalf("expected 1 with keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyPAT)
	if r == dummyPAT {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "patABCDE") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyPAT {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPAT)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyPAT)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPAT)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
