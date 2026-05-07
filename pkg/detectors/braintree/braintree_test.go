package braintree

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "access_token$production$abcdef0123456789$0123456789abcdef0123456789abcdef"
const dummySandbox = "access_token$sandbox$abcdef0123456789$0123456789abcdef0123456789abcdef"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Braintree {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("BRAINTREE=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) != "abcdef0123456789" {
		t.Fatalf("expected RawV2=merchant, got %q", res[0].RawV2)
	}
}

func TestFromData_NoMatch(t *testing.T) {
	body := []byte("access_token=plain")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummySandbox {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBaseSandbox
	apiBaseSandbox = srv.URL
	defer func() { apiBaseSandbox = old }()

	v, err := Scanner{}.Verify(context.Background(), dummySandbox)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBaseSandbox
	apiBaseSandbox = srv.URL
	defer func() { apiBaseSandbox = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummySandbox)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBaseSandbox
	apiBaseSandbox = srv.URL
	defer func() { apiBaseSandbox = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummySandbox)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
