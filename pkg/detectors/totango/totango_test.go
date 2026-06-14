//go:build detector_unit

package totango

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Totango {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("TOTANGO_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_FoundTotangoAPI(t *testing.T) {
	body := []byte("totango_api_key=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for totango_api_key")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_VALUE=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- FP regressions -----------------------------------------------

// Prose mentioning "totango" without an anchor and a long blob next
// to it must not trigger.
func TestFromData_FP_TotangoProseUnrelatedBlob(t *testing.T) {
	body := []byte("// see totango docs for more; hash=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("totango-prose FP: expected 0, got %d", len(res))
	}
}

// A 32-64 char alphanumeric blob far from any totango anchor.
func TestFromData_FP_GitSHAOnly(t *testing.T) {
	body := []byte("commit abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("git-SHA-only FP: expected 0, got %d", len(res))
	}
}

// All-zero / repeated-pattern strings satisfy [A-Za-z0-9]{32,64}
// but carry no key material — entropy gate rejects.
func TestFromData_FP_LowEntropyZeros(t *testing.T) {
	zero := "000000000000000000000000000000000000000000000000"
	body := []byte("TOTANGO_TOKEN=" + zero)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy zeros FP: expected 0, got %d", len(res))
	}
}

func TestFromData_FP_LowEntropyRepeated(t *testing.T) {
	rep := "abababababababababababababababababababababababab"
	body := []byte("totango_api_key=" + rep)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy repeated FP: expected 0, got %d", len(res))
	}
}

func TestVerify_NoBase(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || v {
		t.Fatalf("expected unverified without apiBase")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("app-token") != dummy {
			t.Errorf("missing app-token header")
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
