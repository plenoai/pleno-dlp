package gitlab

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
	"github.com/plenoai/pleno-dlp/pkg/connectors/_paginate"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestParseLinkHeader is tested via the shared _paginate package.
func TestParseLinkHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{
			"next + last",
			`<https://gitlab.com/api/v4/groups/foo/projects?page=2>; rel="next", <https://gitlab.com/api/v4/groups/foo/projects?page=5>; rel="last"`,
			"https://gitlab.com/api/v4/groups/foo/projects?page=2",
		},
		{
			"only last",
			`<https://gitlab.com/api/v4/groups/foo/projects?page=5>; rel="last"`,
			"",
		},
		{
			"prev + next",
			`<https://gitlab.com/api/v4/groups/foo/projects?page=1>; rel="prev", <https://gitlab.com/api/v4/groups/foo/projects?page=3>; rel="next"`,
			"https://gitlab.com/api/v4/groups/foo/projects?page=3",
		},
		{
			"keyset cursor",
			`<https://gitlab.com/api/v4/groups/foo/projects?pagination=keyset&per_page=100&id_after=42>; rel="next"`,
			"https://gitlab.com/api/v4/groups/foo/projects?pagination=keyset&per_page=100&id_after=42",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := _paginate.ParseLinkHeader(c.in); got != c.want {
				t.Errorf("ParseLinkHeader(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestInit_RejectsBadConfig ensures Init returns friendly errors for
// each malformed-config shape.
func TestInit_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		expect string
	}{
		{"missing token", Config{Group: "foo"}, "token is required"},
		{"no scope", Config{Token: "t"}, "config.group or config.project must be set"},
		{"both scopes", Config{Token: "t", Group: "foo", Project: "bar/baz"}, "mutually exclusive"},
		{"bad project shape", Config{Token: "t", Project: "abc"}, "namespace/name form"},
		{"bad api base", Config{Token: "t", Project: "a/b", APIBase: "::not-a-url"}, "invalid api_base"},
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

// TestInit_URLNamespace verifies that a project with slashes in the
// namespace (subgroup path) is accepted and URL-encoded for the API call.
func TestInit_URLNamespace(t *testing.T) {
	cfg := Config{Token: "glpat-test", Project: "eng/backend/api"}
	cfgJSON, _ := json.Marshal(cfg)
	conn := &Connector{}
	if err := conn.Init(context.Background(), "test", 0, 0, false, cfgJSON, 1); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

// TestGroupEnumeration_TwoPages exercises Link-header pagination by serving
// two pages from a fake /groups/foo/projects endpoint.
func TestGroupEnumeration_TwoPages(t *testing.T) {
	var page1Hits, page2Hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/groups/foo/projects", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "id_after") || strings.Contains(r.URL.Query().Get("pagination"), "keyset") {
			// For keyset pagination, we test with Link-header style
			// page1 has next, page2 has no next.
			if page1Hits.Load() > 0 && page2Hits.Load() > 0 {
				// Already served both, just return empty
				_ = json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
		}
		if page1Hits.Load() == 0 {
			page1Hits.Add(1)
			w.Header().Set("Link", fmt.Sprintf(`<%s/groups/foo/projects?pagination=keyset&per_page=100&id_after=42>; rel="next"`, srv.URL))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "name": "p1", "path_with_namespace": "foo/p1", "default_branch": "main"},
			})
			return
		}
		page2Hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": 2, "name": "p2", "path_with_namespace": "foo/p2", "default_branch": "main"},
		})
	})

	conn := newConn(t, Config{Token: "glpat-test", Group: "foo", APIBase: srv.URL})
	projects, err := conn.listProjects(context.Background())
	if err != nil {
		t.Fatalf("listProjects: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("got %d projects, want 2", len(projects))
	}
	if projects[0].Name != "p1" || projects[1].Name != "p2" {
		t.Errorf("got names %s,%s want p1,p2", projects[0].Name, projects[1].Name)
	}
}

// TestTreeWalk_MixedNodes asserts the tree walk skips non-blob entries
// and emits one chunk per eligible blob.
func TestTreeWalk_MixedNodes(t *testing.T) {
	body := []byte("glpat-xxxxxxxxxxxxxxxxxxxx\nsecret-data")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// GitLab addresses projects by URL-encoded path when looking up by
	// namespace/name, so the handler must match the encoded form.
	mux.HandleFunc("/projects/foo%2Fmyproject", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                  123,
			"name":                "myproject",
			"path_with_namespace": "foo/myproject",
			"default_branch":      "main",
		})
	})
	mux.HandleFunc("/projects/123/repository/tree", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "abc123", "name": "README.md", "type": "blob", "path": "README.md", "mode": "100644"},
			{"id": "def456", "name": "docs", "type": "tree", "path": "docs", "mode": "040000"},
		})
	})
	mux.HandleFunc("/projects/123/repository/files/README.md/raw", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})

	conn := newConn(t, Config{Token: "glpat-test", Project: "foo/myproject", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if string(chunks[0].Data) != string(body) {
		t.Errorf("data = %q, want %q", chunks[0].Data, body)
	}
	md := chunks[0].SourceMetadata.GitLab
	if md == nil {
		t.Fatal("nil GitLab metadata")
	}
	if md.ProjectID != 123 || md.Path != "README.md" || md.Branch != "main" {
		t.Errorf("metadata = %+v", md)
	}
	if md.Project != "foo/myproject" {
		t.Errorf("project = %q, want foo/myproject", md.Project)
	}
}

// TestOversizeBlob_Skipped verifies that blobs exceeding MaxBlobBytes
// are not emitted as chunks.
func TestOversizeBlob_Skipped(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Register the URL-encoded project path handler.
	mux.HandleFunc("/projects/foo%2Fbar", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                  123,
			"name":                "bar",
			"path_with_namespace": "foo/bar",
			"default_branch":      "main",
		})
	})
	mux.HandleFunc("/projects/123/repository/tree", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "abc", "name": "big.bin", "type": "blob", "path": "big.bin", "mode": "100644"},
		})
	})
	mux.HandleFunc("/projects/123/repository/files/big.bin/raw", func(w http.ResponseWriter, r *http.Request) {
		// Return 6 MiB of data (exceeds the 5 MiB default cap).
		big := make([]byte, 6*1024*1024)
		_, _ = w.Write(big)
	})

	conn := newConn(t, Config{Token: "glpat-test", Project: "foo/bar", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 0 {
		t.Fatalf("got %d chunks, want 0 (oversize blob should be skipped)", len(chunks))
	}
}

// TestClient_BackoffOn429 asserts the client retries on 429 and honours
// Retry-After. The testSleep hook keeps the test quick.
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

	cli := NewClient(srv.URL, "glpat-test", nil)
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

// TestClient_RateLimitBucket exercises the RateLimit-Remaining=0 path.
func TestClient_RateLimitBucket(t *testing.T) {
	var calls atomic.Int32
	resetAt := time.Now().Add(2 * time.Second).Unix()
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("RateLimit-Remaining", "0")
		w.Header().Set("RateLimit-Reset", fmt.Sprint(resetAt))
		_, _ = fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "glpat-test", nil)
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

// TestVerify_OKAndUnauthorized covers the full Verify state matrix:
// 200 → verified, 401 / 403 → not verified.
func TestVerify_OKAndUnauthorized(t *testing.T) {
	var status atomic.Int32
	var seenHeaders atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		seenHeaders.Store(map[string]string{
			"private-token":  r.Header.Get("PRIVATE-TOKEN"),
			"authorization": r.Header.Get("Authorization"),
		})
		w.WriteHeader(int(status.Load()))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Test PAT token (glpat- prefix) → PRIVATE-TOKEN header
	conn := &Connector{}
	conn.SetAPIBase(srv.URL)

	status.Store(http.StatusOK)
	ok, err := conn.Verify(context.Background(), "glpat-real-token")
	if err != nil || !ok {
		t.Errorf("200 PAT: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	h, _ := seenHeaders.Load().(map[string]string)
	if h["private-token"] != "glpat-real-token" {
		t.Errorf("PRIVATE-TOKEN header = %q, want glpat-real-token", h["private-token"])
	}
	if h["authorization"] != "" {
		t.Errorf("Authorization header should be empty for PAT, got %q", h["authorization"])
	}

	// Test Bearer token → Authorization: Bearer header
	status.Store(http.StatusOK)
	ok, err = conn.Verify(context.Background(), "oauth-bearer-token")
	if err != nil || !ok {
		t.Errorf("200 Bearer: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	h, _ = seenHeaders.Load().(map[string]string)
	if h["authorization"] != "Bearer oauth-bearer-token" {
		t.Errorf("Authorization header = %q, want Bearer oauth-bearer-token", h["authorization"])
	}
	if h["private-token"] != "" {
		t.Errorf("PRIVATE-TOKEN should be empty for Bearer, got %q", h["private-token"])
	}

	status.Store(http.StatusUnauthorized)
	ok, err = conn.Verify(context.Background(), "glpat-bad-token")
	if err != nil || ok {
		t.Errorf("401: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}

	status.Store(http.StatusForbidden)
	ok, err = conn.Verify(context.Background(), "glpat-scoped-token")
	if err != nil || ok {
		t.Errorf("403: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}
}

// TestSelfHosted_APIBaseOverride verifies that a custom api_base is used
// for all API calls.
func TestSelfHosted_APIBaseOverride(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var called atomic.Int32
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	conn := &Connector{}
	conn.SetAPIBase(srv.URL)
	ok, err := conn.Verify(context.Background(), "glpat-test")
	if err != nil || !ok {
		t.Errorf("verify against self-hosted: ok=%v err=%v", ok, err)
	}
	if called.Load() != 1 {
		t.Errorf("expected 1 call to self-hosted /user, got %d", called.Load())
	}
}

// TestEndToEnd_ScanGroup drives the connector against a fake group with
// one project and one blob, then asserts a Chunk is emitted with the
// expected metadata.
func TestEndToEnd_ScanGroup(t *testing.T) {
	body := []byte("glpat-xxxxxxxxxxxxxxxxxxxx\nlooks-like-a-token")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/groups/acme/projects", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": 42, "name": "service", "path_with_namespace": "acme/service", "default_branch": "main"},
		})
	})
	mux.HandleFunc("/projects/42/repository/tree", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "envsha", "name": ".env", "type": "blob", "path": ".env", "mode": "100644"},
		})
	})
	mux.HandleFunc("/projects/42/repository/files/.env/raw", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})

	conn := newConn(t, Config{Token: "glpat-test", Group: "acme", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	got := chunks[0]
	if got.SourceType != sources.SourceGitLab {
		t.Errorf("SourceType = %v, want SourceGitLab", got.SourceType)
	}
	if string(got.Data) != string(body) {
		t.Errorf("Data = %q, want %q", got.Data, body)
	}
	md := got.SourceMetadata.GitLab
	if md == nil {
		t.Fatal("nil GitLab metadata")
	}
	if md.ProjectID != 42 || md.Path != ".env" || md.Branch != "main" || md.Group != "acme" {
		t.Errorf("metadata = %+v", md)
	}
	if md.Project != "acme/service" {
		t.Errorf("project = %q, want acme/service", md.Project)
	}
	if md.Sha != "envsha" {
		t.Errorf("sha = %q, want envsha", md.Sha)
	}
}

// TestRegistry confirms init() side-effects: the gitlab connector is
// addressable via both the SaaS connector registry AND the source registry.
func TestRegistry(t *testing.T) {
	c := connectors.New("gitlab")
	if c == nil {
		t.Fatal("connectors.New(\"gitlab\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "gitlab" {
		t.Errorf("descriptor name = %q, want gitlab", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	src := sources.New(sources.SourceGitLab)
	if src == nil {
		t.Fatal("sources.New(SourceGitLab) returned nil")
	}
	if src.Type() != sources.SourceGitLab {
		t.Errorf("Type() = %v, want SourceGitLab", src.Type())
	}
}

// newConn is a test helper that marshals cfg, calls Init, and returns
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
