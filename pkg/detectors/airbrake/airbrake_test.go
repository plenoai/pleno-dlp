package airbrake

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken is a 40-char alphanumeric (the documented Airbrake user-key
// shape, per upstream trufflehog airbrakeuserkey) with high Shannon entropy
// so it clears the 3.5 floor. Not a real credential.
const dummyToken = "aB3xZ9qLpR7mK2vN8sT4wY6hJ1cF5gD0eU2iO3aP"

// lowEntropyToken is a 40-char run that matches the alnum length regex and
// sits next to the airbrake keyword, but is structurally low-information
// (entropy < 3.5) — the FP shape the hardening now rejects.
const lowEntropyToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Airbrake {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("airbrake_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without airbrake keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("airbrake=" + dummyToken + "\nairbrake_api=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("airbrake_token=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy 40-char run near keyword, got %d", len(res))
	}
}

func TestFromData_WrongLengthRejected(t *testing.T) {
	// 44-char alphanumeric: clears the old {40,80} regex but not the
	// documented exact-40 shape.
	body := []byte("airbrake_token=" + dummyToken + "abcd")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for 44-char token, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != dummyToken {
			t.Errorf("query mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false")
	}
}
