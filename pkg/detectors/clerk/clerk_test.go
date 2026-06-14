//go:build detector_unit

package clerk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyTest = "sk_test_AbCdEf0123456789AbCdEf0123456789AbCd"
const dummyLive = "sk_live_ZyXwVu9876543210ZyXwVu9876543210ZyXw"

func TestFromData_TestKey(t *testing.T) {
	body := []byte("# clerk\nCLERK_SECRET_KEY=" + dummyTest)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityHigh {
		t.Fatalf("expected SeverityHigh for test key, got %v", res[0].Severity)
	}
}

func TestFromData_LiveKey_Critical(t *testing.T) {
	body := []byte("# clerk.com\nCLERK_SECRET=" + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical for live key, got %v", res[0].Severity)
	}
}

// Without a `clerk` keyword the detector defers to Stripe — no result
// here means Clerk does not duplicate Stripe-only hits.
func TestFromData_NoClerkKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("STRIPE_SECRET_KEY="+dummyLive))
	if len(res) != 0 {
		t.Fatalf("expected 0 without clerk keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyTest)
	if r == dummyTest {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "sk_test_AbCd") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyLive {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
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

	v, _ := Scanner{}.Verify(context.Background(), dummyLive)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
