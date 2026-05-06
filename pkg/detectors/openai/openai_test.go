package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyKey = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
const dummyProjKey = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDE"
const anthropicKey = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"

func TestFromData_PositiveStandard(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("OPENAI_API_KEY="+dummyKey))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveProject(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+dummyProjKey))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_ExcludeAnthropic(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+anthropicKey))
	if len(res) != 0 {
		t.Fatalf("expected 0 (anthropic must not match openai), got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyKey {
			t.Errorf("auth header mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
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

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}
