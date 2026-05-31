package cohere

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "abcdefghijABCDEFGHIJ0123456789ABCDEFGHIJ"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("COHERE_API_KEY="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("k="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareCohereWord ensures the \bcohere\b alternative arms a token
// so the bare-word keyword path still works alongside the _api_key forms.
func TestFromData_BareCohereWord(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("cohere key: "+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

// TestFromData_CoherentNotArmed guards the false positive the word boundary
// fixes: "coherent answers" must NOT arm a git-SHA-shaped 40-char token.
func TestFromData_CoherentNotArmed(t *testing.T) {
	// 40-char lowercase-hex git SHA shape near English "coherent".
	const sha = "356a192b7913b04c54574d18c28d46e6395428ab"
	data := "the model gives coherent answers; commit " + sha
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(data))
	if len(res) != 0 {
		t.Fatalf("expected 0 (coherent must not arm), got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if !strings.HasPrefix(redact(dummy), "abcdef") {
		t.Fatal("redact prefix wrong")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
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

	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
