//go:build detector_unit

package hookdeck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyTest = "hookdeck_test_abcdef0123456789ABCDEF0123456789ab"
	dummyLive = "hookdeck_live_abcdef0123456789ABCDEF0123456789ab"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Hookdeck {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Test(t *testing.T) {
	body := []byte("HOOKDECK_KEY=" + dummyTest)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_Live(t *testing.T) {
	body := []byte("HOOKDECK_KEY=" + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 for live, got 0")
	}
}

func TestFromData_NoPrefix(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X=abcdef0123456789ABCDEF0123456789ab"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without prefix, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte(dummyTest + "\n" + dummyTest)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyLive {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyTest)
	if v {
		t.Fatal("expected verified=false")
	}
}
