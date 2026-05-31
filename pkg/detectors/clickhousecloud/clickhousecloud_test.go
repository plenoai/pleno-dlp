package clickhousecloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID     = "AbCdEf0123456789AbCdEf0123456789"
	dummySecret = "aaaabbbbccccddddeeeeffff0000111122223333aaaabbbb"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ClickHouseCloud {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# clickhouse_cloud\nID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) == "" {
		t.Fatal("expected RawV2 paired secret")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("ID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("# clickhouse_cloud\nID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}

func swapBase(url string) func() {
	old := apiBase
	apiBase = url
	return func() { apiBase = old }
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/organizations" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyID || p != dummySecret {
			t.Errorf("basic auth mismatch: u=%q p=%q ok=%v", u, p, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer swapBase(srv.URL)()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Rejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		defer swapBase(srv.URL)()

		v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: expected no error, got %v", code, err)
		}
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
	}
}

func TestVerify_TransientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer swapBase(srv.URL)()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
	if v {
		t.Fatal("expected verified=false on 500")
	}
}

func TestVerify_RateLimitedIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	defer swapBase(srv.URL)()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
	if v {
		t.Fatal("expected verified=false on 429")
	}
}

func TestVerify_BadPair(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), "no-colon-here")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false for malformed pair")
	}
}

func TestFromData_VerifySetsVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyID || p != dummySecret {
			t.Errorf("basic auth mismatch in FromData verify")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer swapBase(srv.URL)()

	body := []byte("# clickhouse_cloud\nID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}
