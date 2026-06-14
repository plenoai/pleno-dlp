//go:build detector_unit

package figma

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyLegacy = "figd_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDE"
const dummyPAT = "figpat_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJ"

func TestFromData_Legacy(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("FIGMA_TOKEN="+dummyLegacy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyLegacy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_PAT(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("FIGMA_TOKEN="+dummyPAT))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("figd_short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyLegacy)
	if r == dummyLegacy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "figd_AbCdE") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Figma-Token") != dummyLegacy {
			t.Errorf("token header mismatch: %q", r.Header.Get("X-Figma-Token"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLegacy)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyLegacy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLegacy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
