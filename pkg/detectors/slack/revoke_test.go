// Tests for Slack auth.revoke. Slack's API contract is "always HTTP 200,
// outcome encoded in the JSON body" — these tests pin that mapping plus
// the transport-level (429 / network / empty secret) edge cases.
package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// revokeServer spins an httptest server that asserts the request shape
// (POST /api/auth.revoke, Bearer <token>) and replies with the supplied
// status code + body. Callers swap apiBase to srv.URL via t.Cleanup.
func revokeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/auth.revoke" {
			t.Errorf("expected /api/auth.revoke, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("expected Bearer auth, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func swapBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestRevoke_Success(t *testing.T) {
	srv := revokeServer(t, http.StatusOK, `{"ok":true,"revoked":true}`)
	swapBase(t, srv.URL)

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !got.Revoked {
		t.Fatal("expected Revoked=true on ok+revoked")
	}
	if got.Err != nil {
		t.Errorf("happy path must not populate Err: %v", got.Err)
	}
	if got.RevokedAt.IsZero() {
		t.Error("RevokedAt must be set on successful revoke")
	}
}

// TestRevoke_AlreadyRevoked_TokenRevoked covers the canonical "second
// call after a prior revoke" path. Idempotency contract: Revoked=true
// with Err carrying the diagnostic.
func TestRevoke_AlreadyRevoked_TokenRevoked(t *testing.T) {
	srv := revokeServer(t, http.StatusOK, `{"ok":false,"error":"token_revoked"}`)
	swapBase(t, srv.URL)

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("token_revoked must not be a hard error: %v", err)
	}
	if !got.Revoked {
		t.Fatal("token_revoked must surface as Revoked=true (idempotent)")
	}
	if got.Err == nil {
		t.Error("expected diagnostic Err on idempotent already-revoked")
	}
}

func TestRevoke_AlreadyRevoked_InvalidAuth(t *testing.T) {
	srv := revokeServer(t, http.StatusOK, `{"ok":false,"error":"invalid_auth"}`)
	swapBase(t, srv.URL)

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("invalid_auth must not be a hard error: %v", err)
	}
	if !got.Revoked {
		t.Fatal("invalid_auth must surface as Revoked=true (idempotent)")
	}
	if got.Err == nil {
		t.Error("expected diagnostic Err on invalid_auth")
	}
}

func TestRevoke_AlreadyRevoked_NotAuthed(t *testing.T) {
	srv := revokeServer(t, http.StatusOK, `{"ok":false,"error":"not_authed"}`)
	swapBase(t, srv.URL)

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("not_authed must not be a hard error: %v", err)
	}
	if !got.Revoked {
		t.Fatal("not_authed must surface as Revoked=true (idempotent)")
	}
	if got.Err == nil {
		t.Error("expected diagnostic Err on not_authed")
	}
}

func TestRevoke_UnknownError(t *testing.T) {
	srv := revokeServer(t, http.StatusOK, `{"ok":false,"error":"unknown_error"}`)
	swapBase(t, srv.URL)

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("ok=false unknown_error must not be a hard error: %v", err)
	}
	if got.Revoked {
		t.Fatal("unknown_error must surface as Revoked=false")
	}
	if got.Err == nil {
		t.Error("expected provider error in RevokeResult.Err")
	}
	if !strings.Contains(got.Err.Error(), "unknown_error") {
		t.Errorf("Err should carry the provider error string: %v", got.Err)
	}
}

// TestRevoke_RateLimited asserts 429 -> hard error, no retry. Same
// policy as Verify.
func TestRevoke_RateLimited(t *testing.T) {
	srv := revokeServer(t, http.StatusTooManyRequests, `{}`)
	swapBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("429 must surface as a hard error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error must mention HTTP 429: %v", err)
	}
}

// TestRevoke_NetworkError asserts that a transport-level failure flows
// through the second return value so callers can distinguish "we
// couldn't reach the provider" from "the provider said no".
func TestRevoke_NetworkError(t *testing.T) {
	swapBase(t, "http://127.0.0.1:1") // refused

	got, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("network failure must surface via the second return value")
	}
	if got.Revoked {
		t.Error("must not report Revoked=true on transport failure")
	}
	if got.Err != nil {
		t.Errorf("transport failures must not populate RevokeResult.Err: %v", got.Err)
	}
}

func TestRevoke_EmptySecret(t *testing.T) {
	got, err := Scanner{}.Revoke(context.Background(), "")
	if err == nil {
		t.Fatal("empty secret must surface as a hard error")
	}
	if got.Revoked {
		t.Error("empty secret must not report Revoked=true")
	}
}

// TestRevoke_AuthHeader verifies the bearer header is exactly
// "Bearer <secret>" — Slack rejects other forms (token, basic, etc.).
func TestRevoke_AuthHeader(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"revoked":true}`))
	}))
	t.Cleanup(srv.Close)
	swapBase(t, srv.URL)

	s := Scanner{}
	if _, err := s.Revoke(context.Background(), dummyToken); err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if want := "Bearer " + dummyToken; seen != want {
		t.Errorf("Authorization header mismatch:\n  got:  %q\n  want: %q", seen, want)
	}
}
