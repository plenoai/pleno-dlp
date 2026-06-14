//go:build detector_unit

package azuresas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummySAS = "https://acmestorage.blob.core.windows.net/container/file.txt?sv=2021-08-06&se=2030-01-01T00%3A00%3A00Z&sr=b&sp=r&sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"

func TestFromData_Positive(t *testing.T) {
	body := []byte("AZ_SAS_URL=" + dummySAS)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummySAS {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if !strings.Contains(res[0].Redacted, "sig=...") {
		t.Fatalf("redacted should mask signature, got %q", res[0].Redacted)
	}
}

func TestFromData_Negative_NoSig(t *testing.T) {
	// No sig= param → not a SAS URL.
	body := []byte("https://acmestorage.blob.core.windows.net/container/file.txt?sv=2021-08-06")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v, err := Scanner{}.Verify(context.Background(), srv.URL+"/c/f?sig=xxx")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	v, _ := Scanner{}.Verify(context.Background(), srv.URL+"/c/f?sig=xxx")
	if v {
		t.Fatal("expected verified=false on 403")
	}
}

func TestVerify_TransportError(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), "http://127.0.0.1:1/c/f?sig=xxx")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
