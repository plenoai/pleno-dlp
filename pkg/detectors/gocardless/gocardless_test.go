package gocardless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyLive    = "live_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN_-"
	dummySandbox = "sandbox_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GoCardless {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Live(t *testing.T) {
	body := []byte("gocardless_token=" + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 live, got 0")
	}
}

func TestFromData_Sandbox(t *testing.T) {
	body := []byte("gocardless_secret=" + dummySandbox)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 sandbox, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without gocardless keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("gocardless=" + dummyLive + "\ngocardless=" + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_Live_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyLive {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBaseLive
	apiBaseLive = srv.URL
	defer func() { apiBaseLive = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
	}
}

func TestVerify_Sandbox_OK(t *testing.T) {
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
		t.Fatalf("verified sandbox expected true: err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBaseLive
	apiBaseLive = srv.URL
	defer func() { apiBaseLive = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyLive)
	if v {
		t.Fatal("expected verified=false")
	}
}
