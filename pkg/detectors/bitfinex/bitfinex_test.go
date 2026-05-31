package bitfinex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 43 alnum chars exactly, matching the regex.
const dummyKey = "abcdef0123456789ABCDEF0123456789abcdefABCDE"
const dummySecret = "zyxwvuZYXWVU98765432109876543210zyxwvu01234"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Bitfinex {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("BITFINEX_API_KEY=" + dummyKey + " BITFINEX_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_KEY=" + dummyKey + " UNRELATED_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// 43-char low-entropy runs match the regex but are not real keys; the
// entropy gate (3.5) must reject them even with the keyword present.
const lowEntropyKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const lowEntropySecret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("BITFINEX_API_KEY=" + lowEntropyKey + " BITFINEX_API_SECRET=" + lowEntropySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy culled), got %d", len(res))
	}
}

// A high-entropy key paired with a low-entropy secret must still be
// rejected: the gate requires BOTH tokens to clear the threshold.
func TestFromData_MixedEntropyRejected(t *testing.T) {
	body := []byte("BITFINEX_API_KEY=" + dummyKey + " BITFINEX_API_SECRET=" + lowEntropySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (mixed entropy culled), got %d", len(res))
	}
}

// High-entropy pair with keyword present still detects (recall guard).
func TestFromData_HighEntropyFound(t *testing.T) {
	body := []byte("bitfinex creds " + dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for high-entropy pair")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("bfx-apikey") != dummyKey {
			t.Errorf("missing key header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}
