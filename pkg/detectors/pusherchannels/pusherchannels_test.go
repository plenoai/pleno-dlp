package pusherchannels

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken is a documented-shape Pusher secret: 20-char lowercase alnum
// (the docs' worked examples are lowercase hex). Entropy ~3.92, well above the
// 3.0 floor. Lowercased from the prior fixture because the corrected regex is
// [a-z0-9]{20} per the authoritative format, not [A-Za-z0-9]{20}.
const dummyToken = "abcdef1234567890abcd"

// lowEntropyToken is a 20-char lowercase-alnum run that clears the regex but
// has entropy 0.0 — the false-positive shape the entropy floor now rejects
// even when a pusher keyword is nearby.
const lowEntropyToken = "aaaaaaaaaaaaaaaaaaaa"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PusherChannels {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("pusher_app_secret=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without pusher keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("pusher_secret=" + dummyToken + "\npusher_app_secret=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_LowEntropyRejected(t *testing.T) {
	// Armed by a nearby pusher_secret reference, but the token is a degenerate
	// low-entropy run — must be culled by the entropy floor.
	body := []byte("pusher_secret=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy token, got %d", len(res))
	}
}

func TestFromData_BareKeywordNoArm(t *testing.T) {
	// "pusher" alone (e.g. a CDN script-src URL or dependency name) must not
	// arm a generic 20-char run — only an assignment-style reference does.
	body := []byte("https://js.pusher.com/8.2/ " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without an assignment-style pusher reference, got %d", len(res))
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
