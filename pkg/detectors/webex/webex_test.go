package webex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a realistic Webex access-token shape: 64-char lowercase hex, the
// format the upstream trufflehog detector anchors on (`\b([a-f0-9]{64})\b`).
// High entropy (~3.98 bits/char) so it clears the 3.0 hex floor. Not a real
// secret — the verify path is mocked.
const dummy = "4f9a2c7e1b8d6f30a5c92e7b4d18f6a0c3e95b21d7f48a6c0e3b9d5f72a14c8e"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Webex {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# webex\nWEBEX_ACCESS_TOKEN=" + dummy)
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

func TestFromData_Dedup(t *testing.T) {
	body := []byte("webex_token " + dummy + "\nwebex_token " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	short := strings.Repeat("a", 30)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("webex_token "+short))
	if len(res) != 0 {
		t.Fatalf("expected 0 for too-short token, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected pins the arm-regex gate: a high-entropy
// hex-64 candidate sitting next to a bare "webex" word (no token/key/secret
// reference) must no longer match. Before hardening the radius-256
// strings.Contains gate armed on any "webex" substring.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("see the webex docs for details " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword window, got %d", len(res))
	}
}

// TestFromData_NonHexRejected pins the charset tightening: a 64-char
// high-entropy base62 string (the old `[A-Za-z0-9]{60,160}` regex would have
// matched this) is not lowercase hex and must not match the hardened regex,
// even with an armed keyword nearby.
func TestFromData_NonHexRejected(t *testing.T) {
	nonHex := "Zk9QmX2vRb7TpL4nW8sJ6yH3dF1gN5cA0eUoIqKzVxBwSrMtYuPlDjGhCfEaWnOx"
	body := []byte("webex_token=" + nonHex)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-hex candidate, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected pins the entropy floor: a 64-char hex run of
// repeated nibbles clears the regex but is not a real token and must be culled
// by HasMinEntropy(token, 3.0), even with an armed keyword nearby.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := strings.Repeat("a", 64)
	body := []byte("webex_token=" + lowEntropy)
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
