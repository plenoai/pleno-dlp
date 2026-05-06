package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyClassic = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"                                                    // 36 chars body
const dummyFine = "github_pat_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefghijklmnopqrs" // 82 chars body

func TestFromData_Positive(t *testing.T) {
	body := "leak: " + dummyClassic + " and another " + dummyFine
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("no token here, ghp shorter"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			t.Errorf("missing token auth header: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
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

	v, err := Scanner{}.Verify(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}
