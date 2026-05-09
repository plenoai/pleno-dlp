package notion

import (
	"context"
	"encoding/json"
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
		{"missing token", Config{}, "token is required"},
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

// TestInit_SetsDefaults verifies that Init fills in APIBase and concurrency
// when they are not provided.
func TestInit_SetsDefaults(t *testing.T) {
	cfgJSON, _ := json.Marshal(Config{Token: "secret_test123"})
	conn := &Connector{}
	if err := conn.Init(context.Background(), "test", 0, 0, false, cfgJSON, 0); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if conn.cfg.APIBase != DefaultAPIBase {
		t.Errorf("APIBase = %q, want %q", conn.cfg.APIBase, DefaultAPIBase)
	}
	if conn.concurrency != 1 {
		t.Errorf("concurrency = %d, want 1", conn.concurrency)
	}
}

// TestVerify_OKAndUnauthorized covers the full Verify state matrix: 200
// -> verified, 401 -> not verified.
func TestVerify_OKAndUnauthorized(t *testing.T) {
	var status atomic.Int32
	var seenAuth atomic.Value
	var seenVersion atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		seenVersion.Store(r.Header.Get("Notion-Version"))
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := &Connector{}
	conn.cfg.APIBase = srv.URL

	status.Store(http.StatusOK)
	ok, err := conn.Verify(context.Background(), "secret_real")
	if err != nil || !ok {
		t.Errorf("200: want verified=true err=nil, got verified=%v err=%v", ok, err)
	}
	if got, _ := seenAuth.Load().(string); got != "Bearer secret_real" {
		t.Errorf("Authorization = %q, want Bearer secret_real", got)
	}
	if got, _ := seenVersion.Load().(string); got != NotionVersion {
		t.Errorf("Notion-Version = %q, want %q", got, NotionVersion)
	}

	status.Store(http.StatusUnauthorized)
	ok, err = conn.Verify(context.Background(), "secret_bad")
	if err != nil || ok {
		t.Errorf("401: want verified=false err=nil, got verified=%v err=%v", ok, err)
	}
}

// TestSearchPagination_TwoPages exercises start_cursor pagination by serving
// two pages from a fake /search endpoint.
func TestSearchPagination_TwoPages(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var searchHits atomic.Int32
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		searchHits.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")

		cursor, _ := body["start_cursor"].(string)
		if cursor == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":      "list",
				"has_more":    true,
				"next_cursor": "cursor-page2",
				"results": []map[string]any{
					{"object": "page", "id": "page-1", "url": "https://notion.so/page-1"},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":   "list",
				"has_more": false,
				"results": []map[string]any{
					{"object": "page", "id": "page-2", "url": "https://notion.so/page-2"},
				},
			})
		}
	})
	mux.HandleFunc("/pages/page-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"properties": map[string]any{
				"Name": map[string]any{
					"type":  "title",
					"title": []map[string]any{{"plain_text": "Page One"}},
				},
			},
		})
	})
	mux.HandleFunc("/pages/page-2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"properties": map[string]any{
				"Name": map[string]any{
					"type":  "title",
					"title": []map[string]any{{"plain_text": "Page Two"}},
				},
			},
		})
	})
	mux.HandleFunc("/blocks/page-1/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"type": "paragraph", "id": "b1", "has_children": false,
					"rich_text": []map[string]any{
						{"type": "text", "plain_text": "AKIAIOSFODNN7EXAMPLE", "annotations": map[string]any{"bold": false, "italic": false, "strikethrough": false, "underline": false, "code": false, "color": "default"}},
					}},
			},
		})
	})
	mux.HandleFunc("/blocks/page-2/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results":  []map[string]any{},
		})
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	if searchHits.Load() != 2 {
		t.Errorf("search hits = %d, want 2", searchHits.Load())
	}
	if !strings.Contains(string(chunks[0].Data), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("chunk 0 data = %q, want to contain AWS key", chunks[0].Data)
	}
	if !strings.Contains(string(chunks[0].Data), "Page One") {
		t.Errorf("chunk 0 data = %q, want to contain title", chunks[0].Data)
	}
}

// TestBlockChildrenPagination exercises paginated block children fetching.
func TestBlockChildrenPagination(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"object": "page", "id": "pg1", "url": "https://notion.so/pg1"},
			},
		})
	})
	mux.HandleFunc("/pages/pg1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"properties": map[string]any{
				"Title": map[string]any{
					"type":  "title",
					"title": []map[string]any{{"plain_text": "Big Page"}},
				},
			},
		})
	})
	mux.HandleFunc("/blocks/pg1/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cursor := r.URL.Query().Get("start_cursor")
		if cursor == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":      "list",
				"has_more":    true,
				"next_cursor": "block-page2",
				"results": []map[string]any{
					{"type": "paragraph", "id": "b1", "has_children": false,
						"rich_text": []map[string]any{
							{"type": "text", "plain_text": "first block", "annotations": map[string]any{"bold": false, "italic": false, "strikethrough": false, "underline": false, "code": false, "color": "default"}},
						}},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":   "list",
				"has_more": false,
				"results": []map[string]any{
					{"type": "paragraph", "id": "b2", "has_children": false,
						"rich_text": []map[string]any{
							{"type": "text", "plain_text": "second block", "annotations": map[string]any{"bold": false, "italic": false, "strikethrough": false, "underline": false, "code": false, "color": "default"}},
						}},
				},
			})
		}
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	data := string(chunks[0].Data)
	if !strings.Contains(data, "first block") {
		t.Errorf("missing 'first block' in data: %q", data)
	}
	if !strings.Contains(data, "second block") {
		t.Errorf("missing 'second block' in data: %q", data)
	}
}

// TestDatabaseQuery exercises database row enumeration via
// POST /databases/{id}/query pagination.
func TestDatabaseQuery(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"object": "database", "id": "db1", "url": "https://notion.so/db1"},
			},
		})
	})
	mux.HandleFunc("/databases/db1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{
					"id": "row-1", "url": "https://notion.so/row-1",
					"properties": map[string]any{
						"API Key": map[string]any{
							"type":      "rich_text",
							"rich_text": []map[string]any{{"plain_text": "sk-live-secret-key-12345"}},
						},
						"Environment": map[string]any{
							"type":   "select",
							"select": map[string]any{"name": "production"},
						},
					},
				},
			},
		})
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	data := string(chunks[0].Data)
	if !strings.Contains(data, "sk-live-secret-key-12345") {
		t.Errorf("missing API key in data: %q", data)
	}
	if !strings.Contains(data, "production") {
		t.Errorf("missing 'production' in data: %q", data)
	}
	// Assert NotionMeta for database row.
	meta := chunks[0].SourceMetadata.Notion
	if meta == nil {
		t.Fatal("NotionMeta is nil")
	}
	if meta.Database != "db1" {
		t.Errorf("meta.Database = %q, want db1", meta.Database)
	}
	if meta.PageID != "row-1" {
		t.Errorf("meta.PageID = %q, want row-1", meta.PageID)
	}
	if !strings.HasPrefix(meta.Part, "database_row:") {
		t.Errorf("meta.Part = %q, want prefix database_row:", meta.Part)
	}
}

// TestRateLimit_BackoffOn429 asserts the client retries on 429 and
// honours Retry-After.
func TestRateLimit_BackoffOn429(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results":  []map[string]any{},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 0 {
		t.Errorf("got %d chunks, want 0 from empty workspace", len(chunks))
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2 (one 429, one 200)", got)
	}
}

// TestPartialFailure_Page404 asserts that a 404 on one page does not abort
// scanning the rest.
func TestPartialFailure_Page404(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"object": "page", "id": "page-missing", "url": "https://notion.so/page-missing"},
				{"object": "page", "id": "page-ok", "url": "https://notion.so/page-ok"},
			},
		})
	})
	mux.HandleFunc("/pages/page-missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not found"}`))
	})
	mux.HandleFunc("/pages/page-ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"properties": map[string]any{
				"Name": map[string]any{
					"type":  "title",
					"title": []map[string]any{{"plain_text": "OK Page"}},
				},
			},
		})
	})
	mux.HandleFunc("/blocks/page-ok/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results":  []map[string]any{},
		})
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1 (404 page should be skipped)", len(chunks))
	}
	if !strings.Contains(string(chunks[0].Data), "OK Page") {
		t.Errorf("chunk data = %q, want to contain 'OK Page'", chunks[0].Data)
	}
}

// TestNotionVersionHeader ensures every request sends the pinned
// Notion-Version header.
func TestNotionVersionHeader(t *testing.T) {
	var gotVersion atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		gotVersion.Store(r.Header.Get("Notion-Version"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results":  []map[string]any{},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	_ = drainChunks(t, conn)

	if got, _ := gotVersion.Load().(string); got != NotionVersion {
		t.Errorf("Notion-Version header = %q, want %q", got, NotionVersion)
	}
}

// TestRegistry confirms init() side-effects.
func TestRegistry(t *testing.T) {
	c := connectors.New("notion")
	if c == nil {
		t.Fatal("connectors.New(\"notion\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "notion" {
		t.Errorf("descriptor name = %q, want notion", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	if len(d.AuthModes) == 0 || d.AuthModes[0] != connectors.AuthBearer {
		t.Errorf("auth modes = %v, want [AuthBearer]", d.AuthModes)
	}
	src := sources.New(sources.SourceNotion)
	if src == nil {
		t.Fatal("sources.New(SourceNotion) returned nil")
	}
	if src.Type() != sources.SourceNotion {
		t.Errorf("Type() = %v, want SourceNotion", src.Type())
	}
}

// TestDatabaseQueryPagination exercises multi-page database query results.
func TestDatabaseQueryPagination(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"object": "database", "id": "db1", "url": "https://notion.so/db1"},
			},
		})
	})
	mux.HandleFunc("/databases/db1/query", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cursor, _ := body["start_cursor"].(string)
		w.Header().Set("Content-Type", "application/json")
		if cursor == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":      "list",
				"has_more":    true,
				"next_cursor": "db-page2",
				"results": []map[string]any{
					{
						"id": "row-1", "url": "https://notion.so/row-1",
						"properties": map[string]any{
							"Key": map[string]any{
								"type":  "title",
								"title": []map[string]any{{"plain_text": "row-1-key"}},
							},
						},
					},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object":   "list",
				"has_more": false,
				"results": []map[string]any{
					{
						"id": "row-2", "url": "https://notion.so/row-2",
						"properties": map[string]any{
							"Key": map[string]any{
								"type":  "title",
								"title": []map[string]any{{"plain_text": "row-2-key"}},
							},
						},
					},
				},
			})
		}
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
}

// TestEndToEnd_MixedPagesAndDatabases drives the connector against a fake
// workspace with pages and databases and asserts correct chunk emission
// including NotionMeta population.
func TestEndToEnd_MixedPagesAndDatabases(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"object": "page", "id": "pg1", "url": "https://notion.so/pg1"},
				{"object": "database", "id": "db1", "url": "https://notion.so/db1"},
			},
		})
	})
	mux.HandleFunc("/pages/pg1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"properties": map[string]any{
				"Name": map[string]any{
					"type":  "title",
					"title": []map[string]any{{"plain_text": "Secrets Doc"}},
				},
			},
		})
	})
	mux.HandleFunc("/blocks/pg1/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{"type": "paragraph", "id": "b1", "has_children": false,
					"rich_text": []map[string]any{
						{"type": "text", "plain_text": "AWS key: AKIAIOSFODNN7EXAMPLE", "annotations": map[string]any{"bold": false, "italic": false, "strikethrough": false, "underline": false, "code": false, "color": "default"}},
					}},
			},
		})
	})
	mux.HandleFunc("/databases/db1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":   "list",
			"has_more": false,
			"results": []map[string]any{
				{
					"id": "row-1", "url": "https://notion.so/row-1",
					"properties": map[string]any{
						"Token": map[string]any{
							"type":      "rich_text",
							"rich_text": []map[string]any{{"plain_text": "ghp_abcdef1234567890"}},
						},
					},
				},
			},
		})
	})

	conn := newConn(t, Config{Token: "secret_test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2 (1 page + 1 db row)", len(chunks))
	}

	for i, ch := range chunks {
		if ch.SourceType != sources.SourceNotion {
			t.Errorf("chunk %d: SourceType = %v, want SourceNotion", i, ch.SourceType)
		}
		if ch.SourceMetadata.Notion == nil {
			t.Errorf("chunk %d: NotionMeta is nil", i)
		}
	}

	foundAWS := false
	foundGitHub := false
	for _, ch := range chunks {
		data := string(ch.Data)
		if strings.Contains(data, "AKIAIOSFODNN7EXAMPLE") {
			foundAWS = true
			// Page chunk metadata assertions.
			meta := ch.SourceMetadata.Notion
			if meta == nil {
				continue
			}
			if meta.PageID != "pg1" {
				t.Errorf("page meta.PageID = %q, want pg1", meta.PageID)
			}
			if meta.Title != "Secrets Doc" {
				t.Errorf("page meta.Title = %q, want 'Secrets Doc'", meta.Title)
			}
			if meta.Part != "page" {
				t.Errorf("page meta.Part = %q, want 'page'", meta.Part)
			}
			if meta.URL != "https://notion.so/pg1" {
				t.Errorf("page meta.URL = %q, want https://notion.so/pg1", meta.URL)
			}
		}
		if strings.Contains(data, "ghp_abcdef1234567890") {
			foundGitHub = true
			// Database row metadata assertions.
			meta := ch.SourceMetadata.Notion
			if meta == nil {
				continue
			}
			if meta.PageID != "row-1" {
				t.Errorf("db row meta.PageID = %q, want row-1", meta.PageID)
			}
			if meta.Database != "db1" {
				t.Errorf("db row meta.Database = %q, want db1", meta.Database)
			}
			if !strings.HasPrefix(meta.Part, "database_row:") {
				t.Errorf("db row meta.Part = %q, want prefix 'database_row:'", meta.Part)
			}
		}
	}
	if !foundAWS {
		t.Error("no chunk contains the AWS key from the page")
	}
	if !foundGitHub {
		t.Error("no chunk contains the GitHub PAT from the database row")
	}
}

// ---- helpers ------------------------------------------------------------

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
