package twitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 30-char lowercase base36 value matching the documented Twitch
// client_secret shape (`[0-9a-z]{30}`, trufflehog upstream + twitch-cli#4).
// Entropy ~4.64, clears the 3.5 floor. Not a real secret.
const dummy = "k7m2q9x4w1z8p3r6t5n0v7b4c9d2fh"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Twitch {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# twitch\nTWITCH_CLIENT_SECRET=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) < 1 {
		t.Fatalf("expected >=1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm is the FP regression now rejected: a generic
// high-entropy 30-char lowercase run sits near a bare `twitch` mention (an
// embed/CDN URL) but with no assignment-style arm. Before hardening, the bare
// `strings.Contains(window, "twitch")` over radius 256 matched this; the arm
// regex must now reject it.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://player.twitch.tv/?channel=foo for the stream\nbuild_id=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-no-arm FP, got %d", len(res))
	}
}

// TestFromData_UppercaseRejected confirms the lowercase base36 charset discards
// mixed-case 30-char runs (e.g. build IDs) that the old `[A-Za-z0-9]` shape
// matched, even when armed.
func TestFromData_UppercaseRejected(t *testing.T) {
	const mixed = "K7M2Q9x4W1z8P3r6T5n0V7b4C9d2Fh"
	body := []byte("TWITCH_CLIENT_SECRET=" + mixed)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for mixed-case run, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected confirms the entropy floor rejects a
// 30-char lowercase run with no secret-grade randomness, even when armed.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("twitch_secret=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, dummy[:8]) {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "OAuth "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
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
		t.Fatal("expected verified=false on transport error")
	}
}
