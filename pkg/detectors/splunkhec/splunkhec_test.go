package splunkhec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "12345678-1234-1234-1234-1234567890ab"

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SplunkHEC {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# splunk_hec\nSPLUNK_HEC_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("splunk_hec=" + dummy + "\nsplunk_hec=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_NoAPIBase_NoOps(t *testing.T) {
	// apiBase defaults to "" — Verify must no-op (unverified, no error).
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("expected no error when apiBase empty, got %v", err)
	}
	if v {
		t.Fatal("expected verified=false when apiBase empty")
	}
}

func TestVerify_Accept200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/services/collector/event" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Splunk "+dummy {
			t.Errorf("Authorization = %q, want %q", got, "Splunk "+dummy)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on HTTP 200")
	}
}

func TestVerify_Reject401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("expected no error on explicit reject, got %v", err)
	}
	if v {
		t.Fatal("expected verified=false on HTTP 401")
	}
}

func TestVerify_Reject403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("expected no error on explicit reject, got %v", err)
	}
	if v {
		t.Fatal("expected verified=false on HTTP 403")
	}
}

func TestVerify_Transient500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on HTTP 500")
	}
	if v {
		t.Fatal("expected verified=false on HTTP 500")
	}
}

func TestVerify_Transient429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on HTTP 429")
	}
	if v {
		t.Fatal("expected verified=false on HTTP 429")
	}
}

func TestFromData_VerifySetsVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	body := []byte("# splunk_hec\nSPLUNK_HEC_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}
