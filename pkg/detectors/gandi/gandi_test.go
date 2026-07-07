//go:build detector_unit

package gandi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwx"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Gandi {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("gandi_api_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without gandi keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm is the false-positive regression: a bare
// "gandi" mention near a high-entropy 24-char run must NOT match, because no
// assignment-style arm reference is present. Before the arm-regex gate, the
// radius-256 strings.Contains check would have flagged this.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	// "gandi" appears, but only as prose — not an assignment anchor.
	body := []byte("see the gandi provider notes; build id Xy7Kp2Lm9Qr4Ns6Tv8Wz1Bc")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-no-arm FP shape, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected is the entropy-floor regression: an armed
// reference next to a low-information 24-char run (repeated character) must NOT
// match.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("gandi_api_key=aaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy token, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("gandi=" + dummyToken + "\ngandi_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Apikey "+dummyToken {
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
