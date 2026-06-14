//go:build detector_unit

package klarna

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyUser is a UUID-shaped merchant-portal username. dummyKey carries the
// documented klarna_(live|test)_api_ prefix. Both are fabricated shapes, never
// real credentials.
const dummyUser = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"
const dummyKey = "klarna_live_api_eW91Q2Fubm90U2VlTWVJYW1Ob3RSZWFsMTIzNDU2Nzg5MGFiY2Q"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Klarna {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("KLARNA_USER=" + dummyUser + "\nKLARNA_API_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyKey {
		t.Fatalf("expected Raw=key, got %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyUser+":"+dummyKey {
		t.Fatalf("expected RawV2=user:key, got %q", res[0].RawV2)
	}
}

// TestFromData_TestKey covers the sandbox prefix variant.
func TestFromData_TestKey(t *testing.T) {
	testKey := "klarna_test_api_dGVzdEtleVNhbmRib3hOb3RSZWFsMDk4NzY1NDMyMXp6enp6"
	body := []byte("klarna_api_key = " + testKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 for test-prefixed key, got 0")
	}
	if string(res[0].Raw) != testKey {
		t.Fatalf("expected Raw=test key, got %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	// Key present but no klarna assignment context anywhere near it.
	body := []byte("SOME_TOKEN=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without klarna assignment context, got %d", len(res))
	}
}

// TestFromData_GenericHighEntropyRejected is the FP regression: a generic
// high-entropy 40-char string sitting next to the klarna keyword must NOT match
// now that detection anchors on the klarna_(live|test)_api_ prefix. Under the
// old bare [A-Za-z0-9]{32,64} regex this would have been reported.
func TestFromData_GenericHighEntropyRejected(t *testing.T) {
	body := []byte("klarna_api_key = Zk9q3RbT7xW2pL8sVnH4mC1dY6gA0eU5jB9fQwXz")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for generic high-entropy string lacking the klarna_ prefix, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyUser || p != dummyKey {
			t.Errorf("basic auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
