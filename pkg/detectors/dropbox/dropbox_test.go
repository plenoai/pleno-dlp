package dropbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyShort = "sl." + "abcdefghijABCDEFGHIJ0123456789ABCDEFGHIJabcdefghijABCDEFGHIJ0123456789ABCDEFGHIJabcdefghijABCDEFGHIJ0123456789ABCDEFGHIJ0123456789-_"
const dummyLegacy = "abcdefghijABCDEFGHIJ0123456789AB-_abcdefghijABCDEFGHIJ0123456789"

func TestFromData_Short(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("DROPBOX_TOKEN="+dummyShort))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Legacy_KeywordRequired(t *testing.T) {
	bare := []byte("X-Token: " + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, bare)
	if len(res) != 0 {
		t.Fatalf("legacy without keyword should not match, got %d", len(res))
	}

	withKW := []byte("DROPBOX_APP_TOKEN=" + dummyLegacy)
	res, _ = Scanner{}.FromData(context.Background(), false, withKW)
	if len(res) != 1 {
		t.Fatalf("expected 1 with keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if !strings.HasPrefix(redact(dummyShort), "sl.abcde") {
		t.Fatal("redact prefix wrong")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST")
		}
		body, _ := io.ReadAll(r.Body)
		if strings.TrimSpace(string(body)) != "null" {
			t.Errorf("expected body 'null', got %q", body)
		}
		if r.Header.Get("Authorization") != "Bearer "+dummyShort {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyShort)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyShort)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyShort)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
