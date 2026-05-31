package wasabi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	// Avoid "wasabi" substring in the key body so the no-keyword
	// negative test doesn't accidentally match the contextKeyword.
	dummyKey    = "ZYXWVUTSRQ1234567890"
	dummySecret = "abcdefghijABCDEFGHIJ0123456789klMNOPQRST"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Wasabi {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# wasabi\nWASABI_ACCESS_KEY=" + dummyKey + "\nWASABI_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyKey + "\nY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_AWSPrefixSkipped(t *testing.T) {
	body := []byte("wasabi AKIAIOSFODNN7EXAMPLE secret " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for AKIA prefix, got %d", len(res))
	}
}

func TestFromData_OnlyKey(t *testing.T) {
	body := []byte("wasabi " + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}

// withFakeEndpoint points apiBase at an httptest.Server that always
// responds with the given status, restoring the original on cleanup.
func withFakeEndpoint(t *testing.T, status int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	orig := apiBase
	apiBase = srv.URL
	t.Cleanup(func() {
		apiBase = orig
		srv.Close()
	})
}

func TestVerify_Accept200(t *testing.T) {
	withFakeEndpoint(t, http.StatusOK)
	v, err := verifyPair(context.Background(), dummyKey, dummySecret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Reject403(t *testing.T) {
	withFakeEndpoint(t, http.StatusForbidden)
	v, err := verifyPair(context.Background(), dummyKey, dummySecret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 403")
	}
}

func TestVerify_Transient500(t *testing.T) {
	withFakeEndpoint(t, http.StatusInternalServerError)
	v, err := verifyPair(context.Background(), dummyKey, dummySecret)
	if v {
		t.Fatal("expected verified=false on 500")
	}
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
}

func TestVerify_Transient429(t *testing.T) {
	withFakeEndpoint(t, http.StatusTooManyRequests)
	v, err := verifyPair(context.Background(), dummyKey, dummySecret)
	if v {
		t.Fatal("expected verified=false on 429")
	}
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
}

func TestFromData_VerifiedTrue(t *testing.T) {
	withFakeEndpoint(t, http.StatusOK)
	body := []byte("# wasabi\nWASABI_ACCESS_KEY=" + dummyKey + "\nWASABI_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected >=1 result")
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, got %+v", res[0])
	}
}

func TestVerify_PairAPI(t *testing.T) {
	withFakeEndpoint(t, http.StatusOK)
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true via Verify pair")
	}
}
