package algolia

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyKey = "0123456789abcdef0123456789abcdef"
const dummyApp = "ABCDEF1234"

func TestFromData_Pair(t *testing.T) {
	body := []byte("ALGOLIA_APP_ID=" + dummyApp + "\nALGOLIA_ADMIN_KEY=" + dummyKey)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyKey {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyApp {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyKey))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyKey)
	if r == dummyKey {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Algolia-Application-Id") != dummyApp {
			t.Errorf("app id header mismatch")
		}
		if r.Header.Get("X-Algolia-API-Key") != dummyKey {
			t.Errorf("api key header mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBaseTemplate
	apiBaseTemplate = srv.URL // %s won't appear; Replace is a no-op which is what we want for the test.
	defer func() { apiBaseTemplate = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyApp+":"+dummyKey)
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
	old := apiBaseTemplate
	apiBaseTemplate = srv.URL
	defer func() { apiBaseTemplate = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyApp+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBaseTemplate
	apiBaseTemplate = "http://127.0.0.1:1"
	defer func() { apiBaseTemplate = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyApp+":"+dummyKey)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
