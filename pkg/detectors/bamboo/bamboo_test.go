//go:build detector_unit

package bamboo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Bamboo {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# bamboo\nBAMBOO_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("bamboo " + dummy + "\nbamboo " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("bamboo abc"))
	if len(res) != 0 {
		t.Fatalf("expected 0 for short token, got %d", len(res))
	}
}

const verifyPath = "/rest/api/latest/currentUser.json"

func setAPIBase(t *testing.T, base string) {
	t.Helper()
	old := apiBase
	apiBase = base
	t.Cleanup(func() { apiBase = old })
}

func TestVerify_NoAPIBaseNoOps(t *testing.T) {
	setAPIBase(t, "")
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false (no-op) without apiBase")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != verifyPath {
			t.Errorf("path = %q, want %q", r.URL.Path, verifyPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummy {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Rejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: unexpected err: %v", code, err)
		}
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
	}
}

func TestVerify_TransientErrors(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if err == nil {
			t.Fatalf("code %d: expected transient error", code)
		}
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
	}
}

func TestFromData_VerifyWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	body := []byte("# bamboo\nBAMBOO_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true wired through FromData")
	}
}
