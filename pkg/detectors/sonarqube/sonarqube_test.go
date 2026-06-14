//go:build detector_unit

package sonarqube

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyPrefixed = "squ_abcdef0123456789abcdef0123456789abcdef01"
	dummyLegacy   = "0123456789abcdef0123456789abcdef01234567"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SonarQube {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Prefixed(t *testing.T) {
	body := []byte("# sonar prefixed\nSONAR_TOKEN=" + dummyPrefixed)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyPrefixed {
		t.Fatalf("raw mismatch: %s", res[0].Raw)
	}
}

func TestFromData_LegacyWithKeyword(t *testing.T) {
	body := []byte("# sonarqube\nSONAR_LOGIN=" + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 for legacy with keyword, got 0")
	}
}

func TestFromData_LegacyNoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyLegacy))
	if len(res) != 0 {
		t.Fatalf("expected 0 for legacy without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("sonar " + dummyPrefixed + "\nsonar " + dummyPrefixed)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyPrefixed+":"))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPrefixed)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyPrefixed)
	if v {
		t.Fatal("expected verified=false")
	}
}
