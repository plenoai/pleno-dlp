package stripe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyLive = "sk_live_abcdefghijklmnopqrstu"
const dummyTest = "sk_test_abcdefghijklmnopqrstu"
const dummyRk = "rk_live_abcdefghijklmnopqrstu"

func TestFromData_PositiveLive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("STRIPE_KEY="+dummyLive))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveTest(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyTest))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveRestricted(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyRk))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyLive)
	if !strings.HasPrefix(r, "sk_live_") {
		t.Fatalf("redact missing prefix: %q", r)
	}
	if strings.Contains(r, "qrstu") {
		t.Fatalf("redact leaked tail: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyLive {
			t.Errorf("auth header mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
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

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}
