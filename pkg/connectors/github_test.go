package connectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGitHubAppTokenProviderRefreshesInstallationToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	now := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	var tokenCalls int
	var seenAuth []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			tokenCalls++
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s, want POST", r.Method)
			}
			if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") || strings.Count(strings.TrimPrefix(auth, "Bearer "), ".") != 2 {
				t.Fatalf("token request Authorization must be a bearer JWT, got %q", auth)
			}
			writeJSON(t, w, githubAppTokenResp{
				Token:     "installation-token-" + strconv.Itoa(tokenCalls),
				ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339),
			})
		case "/rate_limit":
			seenAuth = append(seenAuth, r.Header.Get("Authorization"))
			writeJSON(t, w, map[string]any{"ok": true})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	auth, err := newGitHubAppTokenProvider(Config{
		"api_base":            srv.URL,
		"app_id":              "123",
		"app_installation_id": "42",
		"app_private_key":     string(keyPEM),
	})
	if err != nil {
		t.Fatalf("newGitHubAppTokenProvider: %v", err)
	}
	auth.now = func() time.Time { return now }
	cli := newGitHubClient(srv.URL, auth)
	for i := 0; i < 2; i++ {
		resp, err := cli.do(context.Background(), http.MethodGet, "/rate_limit", nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if tokenCalls != 2 {
		t.Fatalf("tokenCalls = %d, want 2 refreshes for near-expiry tokens", tokenCalls)
	}
	if got, want := strings.Join(seenAuth, ","), "Bearer installation-token-1,Bearer installation-token-2"; got != want {
		t.Fatalf("seen auth = %q, want %q", got, want)
	}
}

func TestGitHubAuthProviderRejectsAmbiguousAuth(t *testing.T) {
	_, err := newGitHubAuthProvider(Config{
		"token":               "ghp_test",
		"app_id":              "123",
		"app_installation_id": "42",
		"app_private_key":     "pem",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive auth error, got %v", err)
	}
}

func TestNormalizePEMNewlines(t *testing.T) {
	got := normalizePEMNewlines(`-----BEGIN KEY-----\nabc\n-----END KEY-----`)
	if !strings.Contains(got, "\nabc\n") {
		t.Fatalf("escaped PEM newlines were not normalized: %q", got)
	}
}

// GitHub の listing API は巨大 org の数時間 scan 中に 502/503/504 を返すことが
// あり、 1 回の transient で fingerprint まるごと投げ捨てると無駄が大きい。
// GET だけは GitHub 側の transient を吸収する。
func TestGitHubClientRetriesTransient5xxOnGet(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"message":"Server Error"}`))
			return
		}
		writeJSON(t, w, map[string]any{"ok": true})
	}))
	t.Cleanup(srv.Close)

	cli := newGitHubClient(srv.URL, nil)
	cli.testSleep = func(time.Duration) {}
	resp, err := cli.do(context.Background(), http.MethodGet, "/rate_limit", nil)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	_ = resp.Body.Close()
	if calls != 3 {
		t.Fatalf("calls = %d, want 3 (two 502s then 200)", calls)
	}
}

// 副作用ありの POST は同じ idempotency 保証が無いので 5xx でも retry せず、
// 上位に resp をそのまま戻す。 上位の getJSON 等が status を見て err 化する。
func TestGitHubClientDoesNotRetry5xxOnPost(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	}))
	t.Cleanup(srv.Close)

	cli := newGitHubClient(srv.URL, nil)
	cli.testSleep = func(time.Duration) {}
	resp, err := cli.do(context.Background(), http.MethodPost, "/whatever", nil)
	if err != nil {
		t.Fatalf("c.do should not error on 5xx for non-GET, got %v", err)
	}
	_ = resp.Body.Close()
	if calls != 1 {
		t.Fatalf("POST should not retry on 5xx; calls = %d, want 1", calls)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("encode response: %v", err)
	}
}
