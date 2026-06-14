//go:build detector_unit

package tenable

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyAccess = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	dummySecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Tenable {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# tenable\nTENABLE_ACCESS_KEY=" + dummyAccess + "\nTENABLE_SECRET_KEY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyAccess || string(res[0].RawV2) != dummySecret {
		t.Fatalf("pair mismatch: raw=%s rawv2=%s", res[0].Raw, res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("ACCESS_KEY=" + dummyAccess + "\nSECRET_KEY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without tenable keyword, got %d", len(res))
	}
}

func TestFromData_OnlyAccess(t *testing.T) {
	body := []byte("tenable: ACCESS_KEY=" + dummyAccess)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 with only access key, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	short := strings.Repeat("a", 32)
	body := []byte("tenable: ACCESS_KEY=" + short + "\nSECRET_KEY=" + short)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for too-short, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "accessKey=" + dummyAccess + "; secretKey=" + dummySecret
		if r.Header.Get("X-ApiKeys") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("X-ApiKeys"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAccess+":"+dummySecret)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyAccess+":"+dummySecret)
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
