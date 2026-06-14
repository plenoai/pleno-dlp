//go:build detector_unit

package mongodbatlas

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyPub = "abcdefgh"
const dummyPriv = "01234567-89ab-cdef-0123-456789abcdef"

func TestFromData_Pair(t *testing.T) {
	body := []byte("MONGODB_ATLAS_PUBLIC_KEY=" + dummyPub + "\nMONGODB_ATLAS_PRIVATE_KEY=" + dummyPriv)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyPub {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if string(res[0].Raw) != dummyPriv {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_PrivateKeyOnly_NoPair(t *testing.T) {
	// No 8-letter token anywhere — Raw must surface, RawV2 must stay empty,
	// and Verified must be false (we can't probe Atlas without the public
	// half).
	body := []byte("# atlas\nPRIV=" + dummyPriv)
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

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// UUID alone, no atlas/mongodb keyword in the window → must skip.
	body := []byte("uuid=" + dummyPriv)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyPriv)
	if r == dummyPriv {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic auth: base64(pub:priv)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyPub+":"+dummyPriv))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPub+":"+dummyPriv)
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

	v, err := Scanner{}.Verify(context.Background(), dummyPub+":"+dummyPriv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
