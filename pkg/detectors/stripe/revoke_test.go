package stripe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const dummyRkTest = "rk_test_abcdefghijklmnopqrstuvwx"
const dummyRkLive = "rk_live_abcdefghijklmnopqrstuvwx"

// withAPIBase swaps apiBase for the duration of a test. We restore it via
// the returned cleanup so parallel-safe tests don't leak the override.
func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestRevoke_Happy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummyRkTest {
			t.Errorf("auth header = %q, want Bearer %s", got, dummyRkTest)
		}
		if !strings.Contains(r.URL.Path, dummyRkTest) {
			t.Errorf("path %q does not contain key", r.URL.Path)
		}
		if !strings.HasSuffix(r.URL.Path, "/revoke") {
			t.Errorf("path %q does not end with /revoke", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"rk_test_x","object":"api_key","revoked":true}`))
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatalf("expected Revoked=true, got %+v", res)
	}
	if res.RevokedAt.IsZero() {
		t.Errorf("expected RevokedAt to be stamped")
	}
	if res.ProviderID == "" {
		t.Errorf("expected ProviderID to be populated")
	}
	if !strings.HasPrefix(res.ProviderID, "rk_test_") {
		t.Errorf("ProviderID = %q, want rk_test_ prefix", res.ProviderID)
	}
	if strings.Contains(res.ProviderID, "qrstuvwx") {
		t.Errorf("ProviderID leaks tail of secret: %q", res.ProviderID)
	}
}

func TestRevoke_Live(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"revoked":true}`))
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyRkLive)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatalf("expected Revoked=true")
	}
}

func TestRevoke_RevokedFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"revoked":false,"reason":"already_revoked"}`))
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err != nil {
		t.Fatalf("expected no hard error, got %v", err)
	}
	if res.Revoked {
		t.Fatalf("expected Revoked=false")
	}
	if res.Err == nil {
		t.Fatalf("expected non-fatal Err to carry provider message")
	}
}

func TestRevoke_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err != nil {
		t.Fatalf("404 must not hard-error: %v", err)
	}
	if !res.Revoked {
		t.Fatalf("404 must surface as Revoked=true (idempotent)")
	}
	if res.Err == nil {
		t.Errorf("expected diagnostic Err alongside idempotent success")
	}
}

func TestRevoke_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err == nil {
		t.Fatal("expected hard error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention 401: %v", err)
	}
}

func TestRevoke_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err == nil {
		t.Fatal("expected hard error on 429")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should mention 429: %v", err)
	}
}

func TestRevoke_OtherStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyRkTest)
	if err == nil {
		t.Fatal("expected hard error on 500")
	}
}

func TestRevoke_RejectsSecretKey(t *testing.T) {
	// sk_live_ / sk_test_ have no programmatic revoke endpoint; we MUST
	// hard-error so callers don't believe the rotation happened.
	for _, k := range []string{
		"sk_live_abcdefghijklmnopqrstu",
		"sk_test_abcdefghijklmnopqrstu",
	} {
		_, err := Scanner{}.Revoke(context.Background(), k)
		if err == nil {
			t.Fatalf("Revoke(%q) must reject sk_ keys", k)
		}
		if !strings.Contains(err.Error(), "rk_test_") {
			t.Errorf("error should explain rk_ requirement: %v", err)
		}
	}
}

func TestRevoke_EmptySecret(t *testing.T) {
	_, err := Scanner{}.Revoke(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty secret")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty: %v", err)
	}
}

func TestRevoke_NetworkError(t *testing.T) {
	// Point at a closed server so the HTTP Do() surfaces a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	withAPIBase(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Scanner{}.Revoke(ctx, dummyRkTest)
	if err == nil {
		t.Fatal("expected network error against closed server")
	}
}
