package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestParseLinkHeader verifies the Link-header cursor extractor against
// the shapes GitHub actually emits — first/next/last triples, missing
// next, and empty headers.
func TestParseLinkHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{
			"next + last",
			`<https://api.github.com/orgs/foo/repos?page=2>; rel="next", <https://api.github.com/orgs/foo/repos?page=5>; rel="last"`,
			"https://api.github.com/orgs/foo/repos?page=2",
		},
		{
			"only last",
			`<https://api.github.com/orgs/foo/repos?page=5>; rel="last"`,
			"",
		},
		{
			"prev + next",
			`<https://api.github.com/orgs/foo/repos?page=1>; rel="prev", <https://api.github.com/orgs/foo/repos?page=3>; rel="next"`,
			"https://api.github.com/orgs/foo/repos?page=3",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := parseLinkHeader(c.in); got != c.want {
				t.Errorf("parseLinkHeader(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestInit_RejectsBadConfig ensures Init returns friendly errors for
// each malformed-config shape rather than silently scanning nothing.
func TestInit_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		expect string
	}{
		{"missing token", Config{Org: "foo"}, "token is required"},
		{"no scope", Config{Token: "t"}, "config.org or config.repo"},
		{"both scopes", Config{Token: "t", Org: "foo", Repo: "a/b"}, "mutually exclusive"},
		{"bad repo shape", Config{Token: "t", Repo: "abc"}, "owner/name form"},
		{"bad api base", Config{Token: "t", Repo: "a/b", APIBase: "::not-a-url"}, "invalid api_base"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cfgJSON, err := json.Marshal(c.cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			conn := &Connector{}
			err = conn.Init(context.Background(), "test", 0, 0, false, cfgJSON, 1)
			if err == nil {
				t.Fatalf("Init should have failed")
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("Init err %q does not contain %q", err, c.expect)
			}
		})
	}
}

// TestOrgEnumeration_TwoPages exercises Link-header pagination by serving
// two pages from a fake /orgs/foo/repos endpoint and asserting the
// connector follows the rel="next" cursor end-to-end.
func TestOrgEnumeration_TwoPages(t *testing.T) {
	var page1Hits, page2Hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/orgs/foo/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			page2Hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "r2", "owner": map[string]any{"login": "foo"}, "default_branch": "main"},
			})
			return
		}
		page1Hits.Add(1)
		w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/foo/repos?page=2>; rel="next"`, srv.URL))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "r1", "owner": map[string]any{"login": "foo"}, "default_branch": "main"},
		})
	})
	conn := newConn(t, Config{Token: "t", Org: "foo", APIBase: srv.URL})
	repos, err := conn.listRepos(context.Background())
	if err != nil {
		t.Fatalf("listRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repos, want 2", len(repos))
	}
	if got := page1Hits.Load(); got != 1 {
		t.Errorf("page1 hits = %d, want 1", got)
	}
	if got := page2Hits.Load(); got != 1 {
		t.Errorf("page2 hits = %d, want 1", got)
	}
	if repos[0].Name != "r1" || repos[1].Name != "r2" {
		t.Errorf("got names %s,%s want r1,r2", repos[0].Name, repos[1].Name)
	}
}

// TestTreeWalk_MixedNodes asserts the tree walk skips non-blob entries
// and oversize blobs, and emits exactly one chunk per eligible blob.
func TestTreeWalk_MixedNodes(t *testing.T) {
	body := []byte("AKIAIOSFODNN7EXAMPLE\nfoo")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/repos/foo/bar", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":           "bar",
			"owner":          map[string]any{"login": "foo"},
			"default_branch": "main",
			"private":        false,
		})
	})
	mux.HandleFunc("/repos/foo/bar/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": "deadbeef",
			"tree": []map[string]any{
				{"path": "README.md", "type": "blob", "sha": "abc", "size": int64(len(body))},
				{"path": "docs", "type": "tree", "sha": "xyz"},
				{"path": "huge.bin", "type": "blob", "sha": "big", "size": int64(50 << 20)},
			},
		})
	})
	mux.HandleFunc("/repos/foo/bar/git/blobs/abc", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "abc",
			"encoding": "base64",
			"content":  base64.StdEncoding.EncodeToString(body),
			"size":     int64(len(body)),
		})
	})
	// huge.bin and the tree node MUST NOT be fetched; if the connector
	// hits them, fail loudly so the regression is obvious.
	mux.HandleFunc("/repos/foo/bar/git/blobs/big", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("oversize blob should have been skipped, but /git/blobs/big was hit")
		w.WriteHeader(http.StatusInternalServerError)
	})

	conn := newConn(t, Config{Token: "t", Repo: "foo/bar", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if string(chunks[0].Data) != string(body) {
		t.Errorf("data = %q, want %q", chunks[0].Data, body)
	}
	md := chunks[0].SourceMetadata.GitHub
	if md == nil {
		t.Fatal("nil GitHub metadata")
	}
	if md.Owner != "foo" || md.Repo != "bar" || md.Path != "README.md" || md.Sha != "abc" || md.Branch != "main" {
		t.Errorf("metadata = %+v", md)
	}
	if md.Repository != "foo/bar" || md.File != "README.md" {
		t.Errorf("legacy fields not populated: repository=%q file=%q", md.Repository, md.File)
	}
}

// TestBlobBase64Decode exercises every encoding branch the GitHub blob
// API can return: base64 (the documented default), utf-8 (rare passthrough),
// and an unknown encoding (skipped without erroring).
func TestBlobBase64Decode(t *testing.T) {
	body := []byte("hello world")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":           "r",
			"owner":          map[string]any{"login": "o"},
			"default_branch": "main",
		})
	})
	mux.HandleFunc("/repos/o/r/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": "x",
			"tree": []map[string]any{
				{"path": "a", "type": "blob", "sha": "a64", "size": int64(len(body))},
				{"path": "b", "type": "blob", "sha": "butf", "size": int64(len(body))},
				{"path": "c", "type": "blob", "sha": "cunk", "size": int64(len(body))},
			},
		})
	})
	mux.HandleFunc("/repos/o/r/git/blobs/a64", func(w http.ResponseWriter, r *http.Request) {
		// Realistic GitHub blob: base64 with embedded newlines every 60 chars.
		enc := base64.StdEncoding.EncodeToString(body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "a64",
			"encoding": "base64",
			"content":  enc[:5] + "\n" + enc[5:],
		})
	})
	mux.HandleFunc("/repos/o/r/git/blobs/butf", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "butf",
			"encoding": "utf-8",
			"content":  string(body),
		})
	})
	mux.HandleFunc("/repos/o/r/git/blobs/cunk", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "cunk",
			"encoding": "binary",
			"content":  "ignored",
		})
	})

	conn := newConn(t, Config{Token: "t", Repo: "o/r", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	// We expect base64 + utf-8 to emit; the unknown-encoding blob is dropped.
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	for _, ch := range chunks {
		if string(ch.Data) != string(body) {
			t.Errorf("data %q != %q", ch.Data, body)
		}
	}
}

// TestClient_BackoffOn429 asserts the client retries on 429 and honours
// Retry-After. The testSleep hook keeps the test quick by skipping the
// real wall-clock sleep while still proving the wait was computed.
func TestClient_BackoffOn429(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "tok", nil)
	var sleeps []time.Duration
	cli.testSleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	var out struct{}
	if _, err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2 (one 429, one 200)", got)
	}
	if len(sleeps) != 1 {
		t.Errorf("expected exactly one backoff sleep, got %d (%v)", len(sleeps), sleeps)
	}
}

// TestClient_RateLimitBucket exercises the X-RateLimit-Remaining=0 path:
// after a successful response that says the bucket is empty, the next
// request blocks (via the testSleep hook) until reset.
func TestClient_RateLimitBucket(t *testing.T) {
	var calls atomic.Int32
	resetAt := time.Now().Add(2 * time.Second).Unix()
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(resetAt))
		_, _ = fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "tok", nil)
	var slept atomic.Int64
	cli.testSleep = func(d time.Duration) { slept.Add(int64(d)) }
	var out struct{}
	if _, err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("first GetJSON: %v", err)
	}
	if _, err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("second GetJSON: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
	if slept.Load() <= 0 {
		t.Errorf("expected the second call to wait for the bucket reset, but no sleep was observed")
	}
}

// TestVerify_OKAndUnauthorized covers the full Verify state matrix per the
// detectors.Verifier contract: 200 -> verified, 401 / 403 -> not verified.
func TestVerify_OKAndUnauthorized(t *testing.T) {
	var status atomic.Int32
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(status.Load()))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := &Connector{}
	conn.SetAPIBase(srv.URL)

	status.Store(http.StatusOK)
	ok, err := conn.Verify(context.Background(), "real-token")
	if err != nil || !ok {
		t.Errorf("200: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	if got, _ := seenAuth.Load().(string); got != "Bearer real-token" {
		t.Errorf("Authorization header = %q, want Bearer real-token", got)
	}

	status.Store(http.StatusUnauthorized)
	ok, err = conn.Verify(context.Background(), "bad-token")
	if err != nil || ok {
		t.Errorf("401: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}

	status.Store(http.StatusForbidden)
	ok, err = conn.Verify(context.Background(), "scoped-token")
	if err != nil || ok {
		t.Errorf("403: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}
}

// TestEndToEnd_ScanOrg drives the connector against a fake org with one
// repo and one blob, then asserts a Chunk is emitted with the expected
// metadata. This is the race-clean smoke test the C1 milestone hangs on.
func TestEndToEnd_ScanOrg(t *testing.T) {
	body := []byte("AKIA1234567890ABCDEF\nlooks-like-a-key")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "service", "owner": map[string]any{"login": "acme"}, "default_branch": "main", "private": true},
		})
	})
	mux.HandleFunc("/repos/acme/service/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": "head",
			"tree": []map[string]any{
				{"path": ".env", "type": "blob", "sha": "envsha", "size": int64(len(body))},
			},
		})
	})
	mux.HandleFunc("/repos/acme/service/git/blobs/envsha", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "envsha",
			"encoding": "base64",
			"content":  base64.StdEncoding.EncodeToString(body),
			"size":     int64(len(body)),
		})
	})

	conn := newConn(t, Config{Token: "t", Org: "acme", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	got := chunks[0]
	if got.SourceType != sources.SourceGitHub {
		t.Errorf("SourceType = %v, want SourceGitHub", got.SourceType)
	}
	if string(got.Data) != string(body) {
		t.Errorf("Data = %q, want %q", got.Data, body)
	}
	md := got.SourceMetadata.GitHub
	if md == nil {
		t.Fatal("nil GitHub metadata")
	}
	if md.Owner != "acme" || md.Repo != "service" || md.Path != ".env" || md.Branch != "main" || md.Sha != "envsha" {
		t.Errorf("metadata = %+v", md)
	}
	if md.Visibility != "private" {
		t.Errorf("visibility = %q, want private", md.Visibility)
	}
}

// TestRegistry confirms init() side-effects: the github connector is
// addressable via both the SaaS connector registry AND the source
// registry (sources.New(SourceGitHub)) so the engine can drive it.
func TestRegistry(t *testing.T) {
	c := connectors.New("github")
	if c == nil {
		t.Fatal("connectors.New(\"github\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "github" {
		t.Errorf("descriptor name = %q, want github", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	src := sources.New(sources.SourceGitHub)
	if src == nil {
		t.Fatal("sources.New(SourceGitHub) returned nil")
	}
	if src.Type() != sources.SourceGitHub {
		t.Errorf("Type() = %v, want SourceGitHub", src.Type())
	}
}

// newConn is a tiny test helper that marshals cfg, calls Init, and
// returns the connector ready to Chunks/Verify.
func newConn(t *testing.T, cfg Config) *Connector {
	t.Helper()
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	conn := &Connector{}
	if err := conn.Init(context.Background(), "test", 0, 0, false, cfgJSON, 4); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return conn
}

// drainChunks runs Chunks against conn and collects every emitted
// *Chunk. The runner uses a buffered channel + closer goroutine so a
// stalled producer cannot deadlock the test even if the connector
// regresses on its `select { ch <- ; ctx.Done() }` discipline.
func drainChunks(t *testing.T, conn *Connector) []*sources.Chunk {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ch := make(chan *sources.Chunk, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.Chunks(ctx, ch)
		close(ch)
	}()
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	return got
}
