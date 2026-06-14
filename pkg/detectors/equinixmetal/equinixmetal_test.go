//go:build detector_unit

package equinixmetal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEF"

// hexToken is a realistic hex-style 32-char Equinix token whose Shannon
// entropy is ~3.16 bits/char — it passes the 3.0 gate but would be
// over-culled by a 3.5 floor.
const hexToken = "deadbeefdeadbeef00112233aabbccdd"

// lowEntropyToken is a 32-char run with too few distinct symbols; it clears
// the length floor but must be rejected by the entropy gate.
const lowEntropyToken = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.EquinixMetal {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("equinix_metal_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without equinix keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	// Both occurrences use anchored credential shapes (a bare `equinix=` no
	// longer arms a token after hardening).
	body := []byte("metal_token=" + dummyToken + "\nmetal_api_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_BareEquinixNotArmed confirms a bare `equinix` substring no
// longer arms a token — only anchored credential shapes do.
func TestFromData_BareEquinixNotArmed(t *testing.T) {
	body := []byte("equinix=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare equinix= proximity, got %d", len(res))
	}
}

// TestFromData_HexTokenArmed confirms a realistic hex-style token (entropy
// ~3.6) is still detected under an anchored reference — i.e. the 3.0 gate does
// not over-cull it.
func TestFromData_HexTokenArmed(t *testing.T) {
	body := []byte("metal_api_key=" + hexToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected hex-style token to detect, got 0")
	}
}

// TestFromData_LowEntropyRejected confirms a low-entropy 32-char run is
// rejected by the entropy gate even with an anchored reference.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("metal_api_key=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy token to be rejected, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != dummyToken {
			t.Errorf("auth mismatch")
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
