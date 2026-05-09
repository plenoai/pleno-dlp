package bitbucket

import (
	"context"
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

// TestInit_RejectsBadConfig ensures Init returns friendly errors for each
// malformed-config shape.
func TestInit_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		expect string
	}{
		{"missing auth", Config{Workspace: "ws"}, "app_password is required"},
		{"both auth", Config{Token: "t", AppPassword: "pw", Username: "u", Workspace: "ws"}, "mutually exclusive"},
		{"basic without username", Config{AppPassword: "pw", Workspace: "ws"}, "username is required"},
		{"no scope", Config{Token: "t"}, "workspace or config.repo"},
		{"bad api base", Config{Token: "t", Workspace: "ws", APIBase: "::not-a-url"}, "invalid api_base"},
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

// TestWorkspaceEnumeration_TwoPages exercises Bitbucket's "next" URL
// pagination by serving two pages from a fake /2.0/repositories/{ws} endpoint.
func TestWorkspaceEnumeration_TwoPages(t *testing.T) {
	var page1Hits, page2Hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/2.0/repositories/acme", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pagelen") == "" {
			t.Errorf("expected pagelen query parameter")
		}
		// Second page detection: look for page=2 in query or in the
		// Referer-style next URL. For simplicity, return page 1 with a
		// next link, then page 2 without.
		if strings.Contains(r.URL.RawQuery, "page=2") || strings.Contains(r.URL.Path, "page=2") {
			page2Hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(paginatedRepos{
				Values: []repoRef{
					{FullName: "acme/r2", Name: "r2", IsPrivate: false},
				},
			})
			return
		}
		page1Hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedRepos{
			Values: []repoRef{
				{FullName: "acme/r1", Name: "r1", IsPrivate: false},
			},
			Next: srv.URL + "/2.0/repositories/acme?page=2&pagelen=100",
		})
	})

	conn := newConn(t, Config{Token: "t", Workspace: "acme", APIBase: srv.URL})
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
}

// TestSrcTreeWalk_MixedNodes asserts the tree walk skips directories and
// oversize files, and emits exactly one chunk per eligible file.
func TestSrcTreeWalk_MixedNodes(t *testing.T) {
	body := []byte("AKIAIOSFODNN7EXAMPLE\nfoo")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/2.0/repositories/acme/service", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repoRef{
			FullName: "acme/service", Name: "service",
			IsPrivate: true,
			MainBranch: struct{ Name string `json:"name"` }{Name: "main"},
		})
	})

	mux.HandleFunc("/2.0/repositories/acme/service/src/main/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedSrc{
			Values: []srcEntry{
				{Path: "README.md", Type: "commit_file", Size: int64(len(body))},
				{Path: "docs", Type: "commit_directory", Size: 0},
				{Path: "huge.bin", Type: "commit_file", Size: int64(50 << 20)},
			},
		})
	})

	mux.HandleFunc("/2.0/repositories/acme/service/src/main/README.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})

	conn := newConn(t, Config{Token: "t", Repo: "acme/service", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if string(chunks[0].Data) != string(body) {
		t.Errorf("data = %q, want %q", chunks[0].Data, body)
	}
	md := chunks[0].SourceMetadata.Git
	if md == nil {
		t.Fatal("nil Git metadata")
	}
	if md.Repository != "acme/service" || md.File != "README.md" {
		t.Errorf("metadata = %+v", md)
	}
}

// TestClient_BackoffOn429 asserts the client retries on 429 and honours
// Retry-After.
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

	cli := NewClient(srv.URL, "", "", "tok", nil)
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

// TestClient_BasicAuth asserts the client sends Basic auth when app password
// is configured.
func TestClient_BasicAuth(t *testing.T) {
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "myuser", "mypw", "", nil)
	var out struct{}
	if _, err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	got, _ := seenAuth.Load().(string)
	if !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Authorization = %q, want Basic auth", got)
	}
}

// TestClient_BearerAuth asserts the client sends Bearer auth when token is
// configured (Bearer takes priority over Basic).
func TestClient_BearerAuth(t *testing.T) {
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "myuser", "mypw", "mytoken", nil)
	var out struct{}
	if _, err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	got, _ := seenAuth.Load().(string)
	if got != "Bearer mytoken" {
		t.Errorf("Authorization = %q, want Bearer mytoken", got)
	}
}

// TestVerify_OKAndUnauthorized covers the full Verify state matrix: 200 →
// verified, 401 → not verified.
func TestVerify_OKAndUnauthorized(t *testing.T) {
	var status atomic.Int32
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/2.0/user", func(w http.ResponseWriter, r *http.Request) {
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
}

// TestVerify_BasicAuth verifies that when a connector is initialized with
// app password auth, Verify still works (using Bearer for the verify probe).
func TestVerify_BasicAuth(t *testing.T) {
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/2.0/user", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := &Connector{}
	conn.SetAPIBase(srv.URL)

	ok, err := conn.Verify(context.Background(), "my-app-password")
	if err != nil || !ok {
		t.Errorf("200: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	// Verify always uses Bearer (secret passed directly) — matches the
	// GitHub connector pattern where Verify is independent of Init.
	got, _ := seenAuth.Load().(string)
	if got != "Bearer my-app-password" {
		t.Errorf("Authorization = %q, want Bearer my-app-password", got)
	}
}

// TestEndToEnd_ScanRepo drives the connector against a fake repo with one
// file and asserts a Chunk is emitted with the expected metadata.
func TestEndToEnd_ScanRepo(t *testing.T) {
	body := []byte("AKIA1234567890ABCDEF\nlooks-like-a-key")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/2.0/repositories/acme/service", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repoRef{
			FullName: "acme/service", Name: "service",
			IsPrivate: true,
			MainBranch: struct{ Name string `json:"name"` }{Name: "main"},
		})
	})
	mux.HandleFunc("/2.0/repositories/acme/service/src/main/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedSrc{
			Values: []srcEntry{
				{Path: ".env", Type: "commit_file", Size: int64(len(body))},
			},
		})
	})
	mux.HandleFunc("/2.0/repositories/acme/service/src/main/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})

	conn := newConn(t, Config{Token: "t", Repo: "acme/service", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	got := chunks[0]
	if got.SourceType != sources.SourceBitbucket {
		t.Errorf("SourceType = %v, want SourceBitbucket", got.SourceType)
	}
	if string(got.Data) != string(body) {
		t.Errorf("Data = %q, want %q", got.Data, body)
	}
	md := got.SourceMetadata.Git
	if md == nil {
		t.Fatal("nil Git metadata")
	}
	if md.Repository != "acme/service" || md.File != ".env" || md.Commit != "main" {
		t.Errorf("metadata = %+v", md)
	}
}

// TestEndToEnd_ScanWorkspace drives the connector against a fake workspace
// with two repos and asserts all eligible files are emitted as chunks.
func TestEndToEnd_ScanWorkspace(t *testing.T) {
	body1 := []byte("secret-in-r1")
	body2 := []byte("secret-in-r2")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/2.0/repositories/acme", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedRepos{
			Values: []repoRef{
				{FullName: "acme/r1", Name: "r1", IsPrivate: true,
					MainBranch: struct{ Name string `json:"name"` }{Name: "main"}},
				{FullName: "acme/r2", Name: "r2", IsPrivate: false,
					MainBranch: struct{ Name string `json:"name"` }{Name: "develop"}},
			},
		})
	})
	mux.HandleFunc("/2.0/repositories/acme/r1/src/main/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedSrc{
			Values: []srcEntry{
				{Path: "file1.txt", Type: "commit_file", Size: int64(len(body1))},
			},
		})
	})
	mux.HandleFunc("/2.0/repositories/acme/r2/src/develop/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(paginatedSrc{
			Values: []srcEntry{
				{Path: "file2.txt", Type: "commit_file", Size: int64(len(body2))},
			},
		})
	})
	mux.HandleFunc("/2.0/repositories/acme/r1/src/main/file1.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body1)
	})
	mux.HandleFunc("/2.0/repositories/acme/r2/src/develop/file2.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body2)
	})

	conn := newConn(t, Config{Token: "t", Workspace: "acme", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
}

// TestRegistry confirms init() side-effects: the bitbucket connector is
// addressable via both the SaaS connector registry and the source registry.
func TestRegistry(t *testing.T) {
	c := connectors.New("bitbucket")
	if c == nil {
		t.Fatal("connectors.New(\"bitbucket\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "bitbucket" {
		t.Errorf("descriptor name = %q, want bitbucket", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	src := sources.New(sources.SourceBitbucket)
	if src == nil {
		t.Fatal("sources.New(SourceBitbucket) returned nil")
	}
	if src.Type() != sources.SourceBitbucket {
		t.Errorf("Type() = %v, want SourceBitbucket", src.Type())
	}
}

// newConn is a tiny test helper that marshals cfg, calls Init, and returns
// the connector ready to Chunks/Verify.
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

// drainChunks runs Chunks against conn and collects every emitted *Chunk.
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
