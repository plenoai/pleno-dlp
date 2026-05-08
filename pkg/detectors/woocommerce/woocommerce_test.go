package woocommerce

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyCK = "ck_abcdef0123456789abcdef0123456789abcdef01"
	dummyCS = "cs_0123456789abcdef0123456789abcdef01234567"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.WooCommerce {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("WOOCOMMERCE_KEY=" + dummyCK + " WOOCOMMERCE_SECRET=" + dummyCS)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_OnlyCK(t *testing.T) {
	body := []byte("WOO_KEY=" + dummyCK)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no secret half), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyCK+":"+dummyCS))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			t.Errorf("missing basic auth")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyCK+":"+dummyCS)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyCK+":"+dummyCS)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyCK+":"+dummyCS)
	if v {
		t.Fatal("expected verified=false")
	}
}
