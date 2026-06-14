//go:build detector_unit

package modeanalytics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdef0123456789ABCDEF"
const dummyKey = "1234567890abcdef1234567890ABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ModeAnalytics {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("MODEANALYTICS_TOKEN=" + dummyID + "\nMODE_SECRET=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyID + "\nOTHER=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_RejectsNonHexHighEntropy is the FP regression for the hardening:
// generic high-entropy base62 runs (containing non-hex letters g-z) sitting
// right next to the mode_api_token / mode_secret arm references must no longer
// match now that the charset is restricted to hex. Before the fix the bare
// [A-Za-z0-9]{16,80} regex matched these.
func TestFromData_RejectsNonHexHighEntropy(t *testing.T) {
	body := []byte("mode_api_token = Xq9ZpL2mNvB7wKfR3sTjYcH8gW0\nmode_secret = Gz5RtYuIoPqWzXcVbNmKjHgFdSaQwErT")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (non-hex high-entropy run must be rejected), got %d", len(res))
	}
}

// TestFromData_RejectsLowEntropyHex guards the entropy floor: zero-padded /
// repeated-nibble hex runs clear the hex regex but are not credential-grade.
func TestFromData_RejectsLowEntropyHex(t *testing.T) {
	body := []byte("mode_api_token = 000000000000000000000000\nmode_secret = aaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy hex must be rejected), got %d", len(res))
	}
}

// TestFromData_DocumentedShape exercises the authoritative 24-char lowercase
// hex shape from Mode's Discovery API signature-token docs to prove the
// hardening preserves recall on the real documented format.
func TestFromData_DocumentedShape(t *testing.T) {
	body := []byte("mode_access_key = 8b6fdc0a36bf340604a3cedc\nmode_access_secret = 829146cb6c752f51bbbb8c85")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for documented 24-hex shape")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing auth header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}
