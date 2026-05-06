package anthropic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyKey = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789ABCD"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ANTHROPIC_API_KEY="+dummyKey))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyKey {
		t.Errorf("Raw = %q", res[0].Raw)
	}
}

func TestFromData_Negative_OpenAI(t *testing.T) {
	openai := "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+openai))
	if len(res) != 0 {
		t.Fatalf("expected 0 (openai must not match anthropic), got %d", len(res))
	}
}

func TestFromData_Negative_Empty(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != dummyKey {
			t.Errorf("missing x-api-key: %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Error("missing anthropic-version header")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x"}`))
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
