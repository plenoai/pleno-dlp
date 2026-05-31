package sumsub

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "sbx:abcdef0123456789ABCDEFgh:ZYXWVU98"
	dummySecret = "abcdef0123456789ABCDEF0123456789abcdef01"

	// docKey/docSecret mirror the authoritative shape from Sumsub's own usage
	// repo (github.com/SumSubstance/AppTokenUsageExamples): <env>:<alnum>.<alnum>
	// app token and a 32-char alnum secret. These are Sumsub's published
	// sandbox example values, not live credentials.
	docKey    = "sbx:6L6rqHEtRVvBKKt7P1A03k2x.h6OsEOXWpyaXAjvBVNnx3ccXNGTBLHkw"
	docSecret = "EraepapR4Grr2vI1eZWtTkFDhbhsC5EI"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Sumsub {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SUMSUB_APP_TOKEN=" + dummyKey + " SUMSUB_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 paired result, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyKey+":"+dummySecret {
		t.Fatalf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyKey + " UNRELATED=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_DocShape covers the authoritative <env>:<alnum>.<alnum> token
// shape (dot separator) from Sumsub's published example. Recall must hold for
// the real format, not just the legacy colon fixture.
func TestFromData_DocShape(t *testing.T) {
	body := []byte("SUMSUB_APP_TOKEN=" + docKey + " SUMSUB_SECRET_KEY=" + docSecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 paired result for documented shape, got %d", len(res))
	}
	if string(res[0].RawV2) != docKey+":"+docSecret {
		t.Fatalf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

// TestFromData_FP_SecretFarFromKeyword is the regression for the tightened
// gate: a valid-shaped key sits near the keyword, but the only secret-shaped
// high-entropy run is far (>64 bytes) from any `sumsub` reference. Before the
// radius/arm hardening this paired and fired; it must now reject.
func TestFromData_FP_SecretFarFromKeyword(t *testing.T) {
	pad := strings.Repeat(" filler ", 24) // ~192 bytes of distance
	body := []byte("SUMSUB_APP_TOKEN=" + dummyKey + pad + "cache_digest=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (secret too far from keyword), got %d", len(res))
	}
}

// TestFromData_FP_LowEntropySecret rejects a 32+ char alnum run that clears the
// regex and sits next to the keyword but is structured/low-entropy (a padded
// identifier), not a random secret.
func TestFromData_FP_LowEntropySecret(t *testing.T) {
	lowEnt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 'a', entropy 0
	body := []byte("SUMSUB_APP_TOKEN=" + dummyKey + " SUMSUB_SECRET_KEY=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy secret), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyKey+":"+dummySecret))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
