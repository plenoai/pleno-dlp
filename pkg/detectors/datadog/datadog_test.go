package datadog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyAPI = "0123456789abcdef0123456789abcdef"
const dummyAPP = "0123456789abcdef0123456789abcdef01234567"

func TestFromData_Pair(t *testing.T) {
	body := []byte("DD_API_KEY=" + dummyAPI + "\nDD_APP_KEY=" + dummyAPP)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyAPP {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_SingleAPIOnly(t *testing.T) {
	body := []byte("DD_API_KEY=" + dummyAPI)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("RawV2 should be empty: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("single-key match must not be verified")
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyAPI)
	if r == dummyAPI {
		t.Fatalf("redact didn't redact: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") != dummyAPI {
			t.Errorf("DD-API-KEY mismatch")
		}
		if r.Header.Get("DD-APPLICATION-KEY") != dummyAPP {
			t.Errorf("DD-APPLICATION-KEY mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAPI+":"+dummyAPP)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAPI+":"+dummyAPP)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
