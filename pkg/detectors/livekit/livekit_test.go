//go:build detector_unit

package livekit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyKey mirrors the authoritative shape: "API" prefix + 12 alnum chars
// (livekit/protocol guid.New(APIKeyPrefix), Size=12) = 15 chars total.
const dummyKey = "APIabcdefghijkl"

// dummySecret mirrors utils.RandomSecret() = base62 of 32 bytes = exactly 43
// chars of [0-9A-Za-z]. High entropy, all clears the entropy floor.
const dummySecret = "aB3dE7gH9jK2mN4pQ6rS8tV0wX1yZ5cF2hL4nP6qT8u"

// lowEntropySecret is a fixed-length-43 alnum run that clears secretRe but is
// not a random secret. It is the false-positive shape the entropy floor now
// rejects.
const lowEntropySecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.LiveKit {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("LIVEKIT_API_KEY=" + dummyKey + " LIVEKIT_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	found := false
	for _, r := range res {
		if string(r.RawV2) == dummyKey+":"+dummySecret {
			found = true
		}
	}
	if !found {
		t.Fatal("RawV2 missing")
	}
}

// TestFromData_SecretLengthRange locks in recall across the full base62(32-byte)
// length range. RandomSecret yields 43, 44, or 45 chars; a {43}-only pin would
// silently drop the 44- and 45-char secrets (~half of all real secrets).
func TestFromData_SecretLengthRange(t *testing.T) {
	for name, sec := range map[string]string{
		"len44": dummySecret + "K",  // 44 chars
		"len45": dummySecret + "Kv", // 45 chars
	} {
		body := []byte("LIVEKIT_API_KEY=" + dummyKey + " LIVEKIT_API_SECRET=" + sec)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("%s: expected >=1, got 0 (length-pin regression)", name)
		}
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropySecretRejected is the FP regression: a fixed-length
// alnum run armed by a LIVEKIT_API reference but with entropy below the floor
// must not surface, even though it clears the bare length regex.
func TestFromData_LowEntropySecretRejected(t *testing.T) {
	body := []byte("LIVEKIT_API_KEY=" + dummyKey + " LIVEKIT_API_SECRET=" + lowEntropySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy secret rejected), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestVerify_NoApiBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if err != nil || v {
		t.Fatalf("expected unverified no-error, got v=%v err=%v", v, err)
	}
}
