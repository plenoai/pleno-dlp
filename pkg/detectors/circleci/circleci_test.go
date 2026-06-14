//go:build detector_unit

package circleci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CCIPRJ_ + 43 chars in [A-Za-z0-9_-].
const dummyProject = "CCIPRJ_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_aBcD-G"
const dummyHex = "0123456789abcdef0123456789abcdef01234567"

func TestFromData_Project(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("CIRCLECI_TOKEN="+dummyProject))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Hex_KeywordRequired(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyHex))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
	res, _ = Scanner{}.FromData(context.Background(), false, []byte("CIRCLECI_TOKEN="+dummyHex))
	if len(res) != 1 {
		t.Fatalf("expected 1 with keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyProject)
	if r == dummyProject {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "CCIPRJ_A") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Circle-Token") != dummyProject {
			t.Errorf("circle-token mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyProject)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyProject)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyProject)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
