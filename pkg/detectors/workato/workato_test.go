package workato

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a synthetic 64-char lowercase-hex value matching the documented
// Workato auth-token shape (docs.workato.com/api-mgmt/auth-token.html).
const dummy = "ed776fdfbf5003b4aa6bcaafea8f9003ffb6986454822ce7ebb3c1a8efc08348"

// lowEntropyHex is a 64-char hex run that clears the regex but is a structured
// low-information digest (repeated nibble pattern). Even when armed by a nearby
// keyword it must be rejected by the entropy floor — the FP shape this
// hardening targets.
const lowEntropyHex = "0101010101010101010101010101010101010101010101010101010101010101"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Workato {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# workato\nWORKATO_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the radius/arm-regex tightening: a bare
// "workato" substring (no token/key/secret assignment shape) must no longer arm
// even with the candidate close by.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("# see workato docs\ndigest=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword (no arm), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a structured
// low-information 64-hex run armed by a real keyword must be rejected.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("WORKATO_TOKEN=" + lowEntropyHex)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy hex, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
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

	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
