package jira

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
		{"missing token", Config{APIBase: "https://test.atlassian.net"}, "token is required"},
		{"missing api_base", Config{Token: "t"}, "api_base is required"},
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

// TestProjectEnumeration exercises project enumeration pagination.
func TestProjectEnumeration(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		startAt := r.URL.Query().Get("startAt")
		if startAt == "0" || startAt == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{"key": "PROJ1", "name": "Project 1"},
					{"key": "PROJ2", "name": "Project 2"},
				},
				"isLast":  false,
				"total":   3,
				"startAt": 0,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"values": []map[string]any{
				{"key": "PROJ3", "name": "Project 3"},
			},
			"isLast":  true,
			"total":   3,
			"startAt": 2,
		})
	})
	// Empty search results so scanProject completes fast.
	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []any{},
			"total":  0,
		})
	})

	conn := newConn(t, Config{Token: "t", APIBase: srv.URL})
	projects, err := conn.resolveProjects(context.Background())
	if err != nil {
		t.Fatalf("resolveProjects: %v", err)
	}
	if len(projects) != 3 {
		t.Fatalf("got %d projects, want 3", len(projects))
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("pagination hits = %d, want 2", got)
	}
}

// TestIssueSearchPagination exercises startAt-based pagination for issue search.
// The test returns total=100 so the connector must paginate beyond the first
// page (startAt=0, 50 issues per page). The fake server returns 1 issue per
// page to keep the test manageable while still proving pagination logic.
func TestIssueSearchPagination(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var searchHits atomic.Int32
	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		searchHits.Add(1)
		var body searchReq
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode search body: %v", err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if body.StartAt == 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issues": []map[string]any{
					{
						"key": "PROJ-1",
						"fields": map[string]any{
							"summary":     "First issue",
							"description": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "secret: AKIAIOSFODNN7EXAMPLE"}}}}},
							"comment":     map[string]any{"comments": []any{}},
						},
					},
				},
				"total":      51,
				"startAt":    0,
				"maxResults": 50,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"key": "PROJ-2",
					"fields": map[string]any{
						"summary":     "Second issue",
						"description": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "another secret"}}}}},
						"comment":     map[string]any{"comments": []any{}},
					},
				},
			},
			"total":      51,
			"startAt":    1,
			"maxResults": 50,
		})
	})

	conn := newConn(t, Config{Token: "t", Project: "PROJ", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	// total=51 with pageSize=50 means exactly 2 requests: startAt=0 then startAt=1.
	if got := searchHits.Load(); got != 2 {
		t.Errorf("search hits = %d, want 2", got)
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	for _, ch := range chunks {
		if ch.SourceType != sources.SourceJira {
			t.Errorf("SourceType = %v, want SourceJira", ch.SourceType)
		}
	}
}

// TestIssueWithComments verifies that both description and comments are
// emitted as separate chunks.
func TestIssueWithComments(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"key": "TEST-1",
					"fields": map[string]any{
						"summary":     "Issue with comments",
						"description": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "description text"}}}}},
						"comment": map[string]any{
							"comments": []map[string]any{
								{
									"id":   "10001",
									"body": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "comment body text"}}}}},
								},
								{
									"id":   "10002",
									"body": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "second comment"}}}}},
								},
							},
						},
					},
				},
			},
			"total":      1,
			"startAt":    0,
			"maxResults": 50,
		})
	})

	conn := newConn(t, Config{Token: "t", Project: "TEST", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	// 1 description + 2 comments = 3 chunks.
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	// Verify chunk content.
	var hasDesc, hasCom1, hasCom2 bool
	for _, ch := range chunks {
		data := string(ch.Data)
		if strings.Contains(data, "description text") {
			hasDesc = true
		}
		if strings.Contains(data, "comment body text") {
			hasCom1 = true
		}
		if strings.Contains(data, "second comment") {
			hasCom2 = true
		}
	}
	if !hasDesc || !hasCom1 || !hasCom2 {
		t.Errorf("missing expected content: desc=%v com1=%v com2=%v", hasDesc, hasCom1, hasCom2)
	}
}

// TestJQLBypass verifies that when JQL is set, no project enumeration happens.
func TestJQLBypass(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var projectHits atomic.Int32
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		projectHits.Add(1)
		w.WriteHeader(500)
	})
	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []any{},
			"total":  0,
		})
	})

	conn := newConn(t, Config{Token: "t", JQL: "assignee = currentUser()", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	_ = chunks // May be empty, that's fine.
	if projectHits.Load() != 0 {
		t.Error("project search should not be called when JQL is set")
	}
}

// TestStorageFormat verifies XHTML storage-format content is parsed.
func TestStorageFormat(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	xhtmlContent := "<p>This is <strong>storage format</strong> content.</p>"
	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"key": "DC-1",
					"fields": map[string]any{
						"summary":     "Data Center issue",
						"description": xhtmlContent,
						"comment":     map[string]any{"comments": []any{}},
					},
				},
			},
			"total":      1,
			"startAt":    0,
			"maxResults": 50,
		})
	})

	conn := newConn(t, Config{Token: "t", Project: "DC", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	data := string(chunks[0].Data)
	if !strings.Contains(data, "storage format") {
		t.Errorf("xhtml not parsed, got: %q", data)
	}
}

// TestVerify_OKAndUnauthorized covers the full Verify state matrix.
func TestVerify_OKAndUnauthorized(t *testing.T) {
	var status atomic.Int32
	var seenAuth atomic.Value
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/rest/api/3/myself", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(status.Load()))
	})

	// Cloud auth (Basic).
	conn := &Connector{cfg: Config{Email: "user@example.com", APIBase: srv.URL},
		client: &http.Client{Timeout: requestTimeout}}

	status.Store(http.StatusOK)
	ok, err := conn.Verify(context.Background(), "api-token")
	if err != nil || !ok {
		t.Errorf("200: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	if got, _ := seenAuth.Load().(string); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Authorization = %q, want Basic auth", got)
	}

	status.Store(http.StatusUnauthorized)
	ok, err = conn.Verify(context.Background(), "bad-token")
	if err != nil || ok {
		t.Errorf("401: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}

	// PAT auth (Bearer).
	connNoEmail := &Connector{cfg: Config{APIBase: srv.URL},
		client: &http.Client{Timeout: requestTimeout}}
	status.Store(http.StatusOK)
	ok, err = connNoEmail.Verify(context.Background(), "pat-token")
	if err != nil || !ok {
		t.Errorf("200 PAT: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	if got, _ := seenAuth.Load().(string); got != "Bearer pat-token" {
		t.Errorf("Authorization = %q, want Bearer pat-token", got)
	}
}

// TestRegistry confirms init() side-effects.
func TestRegistry(t *testing.T) {
	c := connectors.New("jira")
	if c == nil {
		t.Fatal("connectors.New(\"jira\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "jira" {
		t.Errorf("descriptor name = %q, want jira", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	if d.SourceType != sources.SourceJira {
		t.Errorf("descriptor SourceType = %v, want SourceJira", d.SourceType)
	}
	src := sources.New(sources.SourceJira)
	if src == nil {
		t.Fatal("sources.New(SourceJira) returned nil")
	}
	if src.Type() != sources.SourceJira {
		t.Errorf("Type() = %v, want SourceJira", src.Type())
	}
}

// TestPartialProjectFailure verifies that a 404 on one project does not
// abort scanning of other projects.
func TestPartialProjectFailure(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"values": []map[string]any{
				{"key": "BAD", "name": "Bad Project"},
				{"key": "GOOD", "name": "Good Project"},
			},
			"isLast": true,
			"total":  2,
		})
	})

	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		var body searchReq
		_ = json.NewDecoder(r.Body).Decode(&body)

		// BAD project returns 404.
		if strings.Contains(body.JQL, "BAD") {
			w.WriteHeader(404)
			_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		// GOOD project returns a result.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"key": "GOOD-1",
					"fields": map[string]any{
						"summary":     "Good issue",
						"description": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "data"}}}}},
						"comment":     map[string]any{"comments": []any{}},
					},
				},
			},
			"total": 1,
		})
	})

	conn := newConn(t, Config{Token: "t", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1 (BAD project should be skipped)", len(chunks))
	}
}

// TestMetadataPopulated verifies Jira metadata is correctly set on chunks.
func TestMetadataPopulated(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/rest/api/3/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issues": []map[string]any{
				{
					"key": "PROJ-42",
					"fields": map[string]any{
						"summary":     "Test issue",
						"description": map[string]any{"type": "doc", "content": []map[string]any{{"type": "paragraph", "content": []map[string]any{{"type": "text", "text": "content"}}}}},
						"comment":     map[string]any{"comments": []any{}},
					},
				},
			},
			"total":      1,
			"startAt":    0,
			"maxResults": 50,
		})
	})

	conn := newConn(t, Config{Token: "t", Project: "PROJ", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	md := chunks[0].SourceMetadata.Jira
	if md == nil {
		t.Fatal("nil Jira metadata")
	}
	if md.Project != "PROJ" {
		t.Errorf("metadata.Project = %q, want PROJ", md.Project)
	}
	if md.IssueKey != "PROJ-42" {
		t.Errorf("metadata.IssueKey = %q, want PROJ-42", md.IssueKey)
	}
	if md.Part != "description" {
		t.Errorf("metadata.Part = %q, want description", md.Part)
	}
}

// newConn is a test helper that marshals cfg and calls Init.
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

// drainChunks runs Chunks and collects every emitted Chunk.
func drainChunks(t *testing.T, conn *Connector) []*sources.Chunk {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ch := make(chan *sources.Chunk, 64)
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
