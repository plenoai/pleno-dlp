package connectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingTokenProvider struct{ calls atomic.Int64 }

func (p *countingTokenProvider) Token(context.Context) (string, error) {
	p.calls.Add(1)
	return "secret", nil
}

func TestGitHubClientRejectsUnsafePaginationBeforeAuth(t *testing.T) {
	p := &countingTokenProvider{}
	c := newGitHubClient("https://ghe.example/api/v3", p)
	for _, bad := range []string{"https://evil.example/api/v3/repos?page=2", "http://ghe.example/api/v3/repos?page=2", "https://user@ghe.example/api/v3/repos", "https://ghe.example/outside/repos"} {
		if _, err := c.do(context.Background(), http.MethodGet, bad, nil); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if p.calls.Load() != 0 {
		t.Fatalf("token requested %d times", p.calls.Load())
	}
	if got, err := c.resolveURL("https://ghe.example/api/v3/repos?page=2"); err != nil || got == "" {
		t.Fatalf("same-origin GHE rejected: %v", err)
	}
	public := newGitHubClient("https://api.github.com", nil)
	if _, err := public.resolveURL("https://api.github.com/repositories?page=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := public.resolveURL("https://api.github.com:443/repos"); err != nil {
		t.Fatalf("default port rejected: %v", err)
	}
	for _, bad := range []string{"https://api.github.com/%2e%2e/evil", "https://api.github.com/repos%2Fsecret"} {
		if _, err := public.resolveURL(bad); err == nil {
			t.Fatalf("encoded attack accepted: %s", bad)
		}
	}
}

func TestGitHubRedirectDoesNotForwardTokenCrossOrigin(t *testing.T) {
	received := make(chan string, 1)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer evil.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL+"/steal", http.StatusFound) }))
	defer origin.Close()
	c := newGitHubClient(origin.URL, staticGitHubToken("top-secret"))
	if _, err := c.do(context.Background(), http.MethodGet, "/page", nil); err == nil {
		t.Fatal("redirect accepted")
	}
	select {
	case got := <-received:
		t.Fatalf("redirect target received auth %q", got)
	default:
	}
}

func TestGitHubRateCoordinatorIgnoresStaleResponsesAndIsolatesClients(t *testing.T) {
	c := newGitHubClient("https://stale.example", nil)
	newer := &http.Response{Header: make(http.Header)}
	newer.Header.Set("X-RateLimit-Remaining", "5")
	newer.Header.Set("X-RateLimit-Reset", "200")
	stale := &http.Response{Header: make(http.Header)}
	stale.Header.Set("X-RateLimit-Remaining", "100")
	stale.Header.Set("X-RateLimit-Reset", "100")
	c.observeRateLimit(newer, 2)
	c.observeRateLimit(stale, 1)
	c.coord.mu.Lock()
	constrained := c.coord.constrained
	c.coord.mu.Unlock()
	if !constrained {
		t.Fatal("stale response reopened quota")
	}
	other := newGitHubClient("https://stale.example", staticGitHubToken("different"))
	other.coord.mu.Lock()
	isolated := !other.coord.constrained
	other.coord.mu.Unlock()
	if !isolated {
		t.Fatal("coordinator leaked across clients/credentials")
	}
}

func TestGitHubRateCoordinatorBackpressureCancellationAndRecovery(t *testing.T) {
	c := newGitHubClient("https://rate.example/api/v3", nil)
	c.coord.mu.Lock()
	c.coord.constrained = true
	c.coord.mu.Unlock()
	release, err := c.acquireRatePermit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.acquireRatePermit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("X-RateLimit-Remaining", "100")
	c.observeRateLimit(resp)
	c.coord.mu.Lock()
	constrained := c.coord.constrained
	c.coord.mu.Unlock()
	if constrained {
		t.Fatal("healthy quota stayed constrained")
	}
}

func TestGitHubRateCoordinatorSerializesLowQuotaWorkers(t *testing.T) {
	c := newGitHubClient("https://workers-rate.example/api/v3", nil)
	c.coord.mu.Lock()
	c.coord.constrained = true
	c.coord.mu.Unlock()
	var active, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := c.acquireRatePermit(context.Background())
			if err != nil {
				return
			}
			n := active.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("peak=%d", peak.Load())
	}
	_, throttles := c.rateCoordinationStats()
	if throttles != 8 {
		t.Fatalf("throttles=%d", throttles)
	}
}

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

func TestGitHubAppTokenProviderRefreshWaitersHonorContextWithoutDuplicateRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	now := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	t.Cleanup(release)
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(refreshStarted)
		}
		<-releaseRefresh
		writeJSON(t, w, githubAppTokenResp{Token: "shared-token", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}))
	t.Cleanup(srv.Close)

	provider, err := newGitHubAppTokenProvider(Config{
		"api_base": srv.URL, "app_id": "123", "app_installation_id": "42", "app_private_key": string(keyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }

	type result struct {
		token string
		err   error
	}
	leaderDone := make(chan result, 1)
	go func() {
		token, err := provider.Token(context.Background())
		leaderDone <- result{token, err}
	}()
	<-refreshStarted

	const waiterCount = 20
	waiterDone := make(chan result, waiterCount)
	cancels := make([]context.CancelFunc, waiterCount/2)
	var started sync.WaitGroup
	started.Add(waiterCount)
	for i := 0; i < waiterCount; i++ {
		ctx := context.Background()
		if i < len(cancels) {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancels[i] = cancel
		}
		go func(ctx context.Context) {
			started.Done()
			token, err := provider.Token(ctx)
			waiterDone <- result{token, err}
		}(ctx)
	}
	started.Wait()
	for _, cancel := range cancels {
		cancel()
	}

	for range len(cancels) {
		got := <-waiterDone
		if !errors.Is(got.err, context.Canceled) || got.token != "" {
			t.Fatalf("canceled waiter = (%q, %v), want empty/context.Canceled", got.token, got.err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("refresh calls while owner blocked = %d, want 1", got)
	}
	release()
	if got := <-leaderDone; got.err != nil || got.token != "shared-token" {
		t.Fatalf("leader = (%q, %v)", got.token, got.err)
	}
	for range waiterCount - len(cancels) {
		got := <-waiterDone
		if got.err != nil || got.token != "shared-token" {
			t.Fatalf("successful waiter = (%q, %v)", got.token, got.err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("total refresh calls = %d, want 1", got)
	}
	if token, err := provider.Token(context.Background()); err != nil || token != "shared-token" {
		t.Fatalf("cached token = (%q, %v)", token, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cached call triggered refresh: %d", got)
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

func TestGitHubClientTransient5xxIgnoresRateLimitReset(t *testing.T) {
	reset := time.Now().Add(time.Hour).Unix()
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
	if got := githubTransientBackoff(resp, 2); got != 4*time.Second {
		t.Fatalf("transient 5xx backoff = %s, want 4s", got)
	}
	resp.Header.Set("Retry-After", "3600")
	if got := githubTransientBackoff(resp, 0); got != time.Minute {
		t.Fatalf("server-directed transient backoff = %s, want 1m cap", got)
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

// HTTP/2 stream CANCEL / GOAWAY / connection reset 等で body 読み込みが
// 途中で切れた場合、 同じ page を retry すれば多くは復活する。 fingerprint
// walk 中の 1 page を投げ捨てて scan 全体を捨てるのが惜しいケース。
func TestGitHubClientGetJSONRetriesOnTransientBodyReadErr(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls < 3 {
			// Content-Length を実際より長く宣言してから途中で切ると、
			// client 側で unexpected EOF が起きる (= transient body read err)。
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":`))
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		writeJSON(t, w, map[string]any{"ok": true})
	}))
	t.Cleanup(srv.Close)

	cli := newGitHubClient(srv.URL, nil)
	cli.testSleep = func(time.Duration) {}
	var out map[string]any
	if _, err := cli.getJSON(context.Background(), "/anything", &out); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3 (two truncated body then 200)", calls)
	}
	if v, _ := out["ok"].(bool); !v {
		t.Fatalf("decoded payload missing or false: %#v", out)
	}
}

func TestIsTransientHTTPReadErrCoversObservedSignatures(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{io.ErrUnexpectedEOF, true},
		{io.EOF, true},
		{errString("stream error: stream ID 705; CANCEL; received from peer"), true},
		{errString("http2: server sent GOAWAY and closed the connection"), true},
		{errString("read tcp: connection reset by peer"), true},
		{errString("write tcp: broken pipe"), true},
		{errString("invalid character 'a' looking for beginning of value"), false},
	}
	for _, tc := range cases {
		if got := isTransientHTTPReadErr(tc.err); got != tc.want {
			t.Errorf("isTransientHTTPReadErr(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("encode response: %v", err)
	}
}
