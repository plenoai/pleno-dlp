package mux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID     = "abcdef01-2345-6789-abcd-ef0123456789"
	dummySecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Mux {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("MUX_TOKEN_ID=" + dummyID + "\nMUX_TOKEN_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyID || string(res[0].RawV2) != dummySecret {
		t.Fatalf("pair mismatch")
	}
}

func TestFromData_OnlyID(t *testing.T) {
	body := []byte("MUX_TOKEN_ID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 with only id, got %d", len(res))
	}
}

func TestFromData_NoMuxPrefix(t *testing.T) {
	body := []byte("ID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without mux prefix, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyID || p != dummySecret {
			t.Errorf("basic auth mismatch")
		}
		if !strings.Contains(r.URL.Path, "/video/v1/assets") {
			t.Errorf("path mismatch: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_BadFormat(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), "no-colon")
	if v {
		t.Fatal("expected verified=false for missing colon")
	}
}
