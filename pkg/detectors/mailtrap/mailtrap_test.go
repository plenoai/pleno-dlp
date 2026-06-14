//go:build detector_unit

package mailtrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyz012345"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Mailtrap {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("mailtrap_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without mailtrap keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNotArmed is the FP regression. A generic
// high-entropy alphanumeric run that merely sits near a bare "mailtrap"
// brand/host mention — with no `mailtrap_(api_)?token|key|secret` assignment
// reference in the tight window — must no longer match after the arm-regex +
// radius-64 tightening. Pre-hardening this fired on radius-256 Contains.
func TestFromData_BareKeywordNotArmed(t *testing.T) {
	body := []byte("see https://mailtrap.io for details; build_id=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword FP shape, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected confirms the entropy floor culls a
// low-information run (repeated characters) even when correctly armed.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 chars, entropy 0
	body := []byte("mailtrap_token=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

// TestFromData_ArmedVariants keeps recall on the assignment forms the arm
// regex is meant to accept.
func TestFromData_ArmedVariants(t *testing.T) {
	for _, kw := range []string{"mailtrap_token", "mailtrap-api-key", "MAILTRAP_API_SECRET", "mailtrapkey"} {
		body := []byte(kw + "=" + dummyToken)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("expected >=1 for armed variant %q, got 0", kw)
		}
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Token") != dummyToken {
			t.Errorf("api-token mismatch")
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

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
