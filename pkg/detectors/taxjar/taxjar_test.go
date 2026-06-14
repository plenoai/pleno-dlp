//go:build detector_unit

package taxjar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 32-char lowercase-alnum, high-entropy shape matching the
// documented TaxJar token format (`[a-z0-9]{32}`, per upstream trufflehog).
const dummy = "a7f3c9e21b8d4607f5a2c1e9d8b30746"

// lowEntropyToken clears the 32-char lowercase-alnum regex but is structured
// filler (long repeated run) — it must be rejected by the entropy floor even
// when armed by a nearby reference.
const lowEntropyToken = "aaaaaaaaaaaaaaaaaaaaaaaa00000000"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.TaxJar {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("TAXJAR_API_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected is the FP-regression case: a high-entropy
// 32-char token sitting near a bare "taxjar" mention (a doc URL, a dependency
// name) but with no assignment-style reference must no longer match now that
// the gate is an arm regex rather than a bare substring.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("// see https://developers.taxjar.com for details\nid = " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no arm), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected ensures a structured/low-variety 32-char run
// is dropped by the entropy floor even when armed by a real reference.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("TAXJAR_API_TOKEN=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
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
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}
