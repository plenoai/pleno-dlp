//go:build detector_unit

package hetzner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789ABCDEF01234567"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Hetzner {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("hcloud_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without hetzner keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("hetzner=" + dummyToken + "\nhcloud_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// lowEntropyToken is a 64-char alphanumeric run that clears the length regex
// but is structured (two repeated halves) — not key-grade randomness.
const lowEntropyToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// TestFromData_BareKeywordNoArm guards the FP shape the hardening now rejects:
// a high-entropy 64-char string sitting within the proximity window of a bare
// "hetzner" mention that is NOT an assignment-style credential reference (e.g.
// prose or a doc URL). The arm regex requires a token/key/secret suffix.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see the hetzner docs for details: " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword (no arm) context, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a structured
// 64-char run armed by an assignment reference must still be culled.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("hcloud_token=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy token, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyToken {
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
