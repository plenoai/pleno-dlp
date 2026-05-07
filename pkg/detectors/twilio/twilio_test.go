package twilio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummySID = "AC0123456789abcdef0123456789abcdef"
const dummyToken = "fedcba9876543210fedcba9876543210"

func TestFromData_Pair(t *testing.T) {
	body := []byte("TWILIO_SID=" + dummySID + "\nTWILIO_TOKEN=" + dummyToken)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyToken {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_SIDOnly(t *testing.T) {
	body := []byte("TWILIO_SID=" + dummySID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("RawV2 should be empty: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("single key must not be verified")
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummySID)
	if !strings.HasPrefix(r, "AC") {
		t.Fatalf("missing prefix: %q", r)
	}
	if strings.Contains(r, "abcdef") {
		t.Fatalf("redact leaked: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummySID || p != dummyToken {
			t.Errorf("basic auth mismatch")
		}
		if !strings.Contains(r.URL.Path, dummySID) {
			t.Errorf("path missing sid: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummySID+":"+dummyToken)
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

	v, err := Scanner{}.Verify(context.Background(), dummySID+":"+dummyToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
