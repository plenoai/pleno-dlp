//go:build detector_unit

package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 00 + 40 URL-safe chars.
const dummy = "00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("OKTA_API_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Okta tokens are unverified-by-design (need tenant URL); got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("00short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_NoVerifyWithoutAPIBase(t *testing.T) {
	// apiBase unset (default) => verify=true must still yield Verified=false.
	res, err := Scanner{}.FromData(context.Background(), true, []byte("okta token "+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("no apiBase => must be unverified")
	}
}

func TestVerify_SSWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "SSWS "+dummy {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	ok, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !ok {
		t.Fatal("expected verified=true for matching SSWS token")
	}

	bad, err := Scanner{}.Verify(context.Background(), "00wrongtokenwrongtokenwrongtokenwrongtoken")
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if bad {
		t.Fatal("expected verified=false for 401")
	}
}

// TestVerify_Transient asserts that 500 and 429 are surfaced as transient
// errors (Verified=false, err!=nil) rather than treated as rejection or
// validity — the engine routes these to "verification failed".
func TestVerify_Transient(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		old := apiBase
		apiBase = srv.URL
		ok, err := Scanner{}.Verify(context.Background(), dummy)
		apiBase = old
		srv.Close()
		if ok {
			t.Fatalf("code %d: expected verified=false", code)
		}
		if err == nil {
			t.Fatalf("code %d: expected transient error, got nil", code)
		}
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "00aBcD") {
		t.Fatalf("missing prefix: %q", r)
	}
}
