package adyen

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "AQE1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Adyen {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# adyen\nADYEN_API_KEY=" + dummy)
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

func TestFromData_BadPrefix(t *testing.T) {
	body := []byte("adyen XYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bad prefix, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("adyen " + dummy + "\nadyen " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// verifyServer spins up an httptest server returning the given status and
// rewires apiBase to it for the duration of the test.
func verifyServer(t *testing.T, status int, assertReq func(*http.Request)) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if assertReq != nil {
			assertReq(r)
		}
		w.WriteHeader(status)
	}))
	old := apiBase
	apiBase = srv.URL
	return func() {
		apiBase = old
		srv.Close()
	}
}

func TestVerify_OK(t *testing.T) {
	cleanup := verifyServer(t, http.StatusOK, func(r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v71/paymentMethods" {
			t.Errorf("path = %s, want /v71/paymentMethods", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != dummy {
			t.Errorf("X-API-Key mismatch: %q", r.Header.Get("X-API-Key"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
	})
	defer cleanup()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

// A valid key with a missing merchantAccount yields 400/422 — request reached
// past auth, so it must still verify true.
func TestVerify_AcceptNon401(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity} {
		cleanup := verifyServer(t, status, nil)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		cleanup()
		if err != nil {
			t.Fatalf("status %d: unexpected err: %v", status, err)
		}
		if !v {
			t.Fatalf("status %d: expected verified=true (reached past auth)", status)
		}
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	cleanup := verifyServer(t, http.StatusUnauthorized, nil)
	defer cleanup()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestVerify_TransientServerError(t *testing.T) {
	cleanup := verifyServer(t, http.StatusInternalServerError, nil)
	defer cleanup()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
	if v {
		t.Fatal("expected verified=false on 500")
	}
}

func TestVerify_TransientRateLimit(t *testing.T) {
	cleanup := verifyServer(t, http.StatusTooManyRequests, nil)
	defer cleanup()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
	if v {
		t.Fatal("expected verified=false on 429")
	}
}

func TestFromData_VerifyWiring(t *testing.T) {
	cleanup := verifyServer(t, http.StatusOK, nil)
	defer cleanup()

	body := []byte("adyen ADYEN_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true wired through FromData")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}

func TestFromData_VerifyReject(t *testing.T) {
	cleanup := verifyServer(t, http.StatusUnauthorized, nil)
	defer cleanup()

	body := []byte("adyen ADYEN_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("expected Verified=false on 401")
	}
}
