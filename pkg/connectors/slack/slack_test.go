package slack

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

// TestConversationsList_Pagination exercises cursor-based pagination by
// serving two pages from a fake conversations.list endpoint.
func TestConversationsList_Pagination(t *testing.T) {
	var page1Hits, page2Hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "cursor2" {
			page2Hits.Add(1)
			_ = json.NewEncoder(w).Encode(conversationsListResp{
				OK:       true,
				Channels: []channelInfo{{ID: "C2", Name: "ch2"}},
			})
			return
		}
		page1Hits.Add(1)
		_ = json.NewEncoder(w).Encode(conversationsListResp{
			OK:       true,
			Channels: []channelInfo{{ID: "C1", Name: "ch1"}},
			ResponseMetadata: struct {
				NextCursor string `json:"next_cursor"`
			}{NextCursor: "cursor2"},
		})
	})
	conn := newConn(t, Config{Token: "xoxb-test", APIBase: srv.URL})
	channels, err := conn.resolveChannels(context.Background())
	if err != nil {
		t.Fatalf("resolveChannels: %v", err)
	}
	if len(channels) != 2 {
		t.Fatalf("got %d channels, want 2", len(channels))
	}
	if page1Hits.Load() != 1 || page2Hits.Load() != 1 {
		t.Errorf("page1=%d page2=%d, want 1,1", page1Hits.Load(), page2Hits.Load())
	}
}

// TestChannelHistory_RepliesAndMessages exercises conversations.history
// with a thread parent that triggers a conversations.replies call.
func TestChannelHistory_RepliesAndMessages(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(conversationsListResp{
			OK:       true,
			Channels: []channelInfo{{ID: "C1", Name: "general"}},
		})
	})
	var repliesHits atomic.Int32
	mux.HandleFunc("/api/conversations.history", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(conversationsHistoryResp{
			OK: true,
			Messages: []message{
				{Text: "hello", TS: "1234.0001"},
				{Text: "thread parent", TS: "1234.0002", ThreadTS: "1234.0002"},
				{Text: "top-level with file", TS: "1234.0003", Files: []struct {
					ID                 string `json:"id"`
					Name               string `json:"name"`
					URLPrivateDownload string `json:"url_private_download"`
				}{
					{ID: "F1", Name: "doc.txt", URLPrivateDownload: srv.URL + "/files/F1"},
				}},
			},
		})
	})
	mux.HandleFunc("/api/conversations.replies", func(w http.ResponseWriter, r *http.Request) {
		repliesHits.Add(1)
		_ = json.NewEncoder(w).Encode(conversationsRepliesResp{
			OK: true,
			Messages: []message{
				{Text: "thread parent", TS: "1234.0002", ThreadTS: "1234.0002"},
				{Text: "reply one", TS: "1234.0010", ThreadTS: "1234.0002"},
				{Text: "reply two", TS: "1234.0011", ThreadTS: "1234.0002"},
			},
		})
	})
	mux.HandleFunc("/files/F1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("file content here"))
	})

	conn := newConn(t, Config{Token: "xoxb-test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)

	// Expect: hello, thread parent, top-level with file, file content,
	// reply one, reply two = 6 chunks.
	if len(chunks) != 6 {
		t.Fatalf("got %d chunks, want 6", len(chunks))
	}
	if repliesHits.Load() != 1 {
		t.Errorf("conversations.replies hits = %d, want 1", repliesHits.Load())
	}

	// Verify message content.
	var texts []string
	for _, ch := range chunks {
		texts = append(texts, string(ch.Data))
	}
	wantTexts := []string{"hello", "thread parent", "top-level with file", "file content here", "reply one", "reply two"}
	for _, w := range wantTexts {
		found := false
		for _, got := range texts {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing chunk with text %q in %v", w, texts)
		}
	}

	// Verify metadata.
	for _, ch := range chunks {
		if ch.SourceType != sources.SourceSlack {
			t.Errorf("SourceType = %v, want SourceSlack", ch.SourceType)
		}
		md := ch.SourceMetadata.Slack
		if md == nil {
			t.Fatal("nil Slack metadata")
		}
		if md.Channel != "C1" {
			t.Errorf("Channel = %q, want C1", md.Channel)
		}
	}
}

// TestScopeDegrade_SkipsChannel asserts that when conversations.history
// returns ok:false with missing_scope or channel_not_found, the connector
// skips that channel and continues scanning the rest.
func TestScopeDegrade_SkipsChannel(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(conversationsListResp{
			OK:       true,
			Channels: []channelInfo{{ID: "C_DENIED"}, {ID: "C_OK"}},
		})
	})
	mux.HandleFunc("/api/conversations.history", func(w http.ResponseWriter, r *http.Request) {
		chID := r.URL.Query().Get("channel")
		if chID == "C_DENIED" {
			_ = json.NewEncoder(w).Encode(conversationsHistoryResp{
				OK:    false,
				Error: "missing_scope",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(conversationsHistoryResp{
			OK:       true,
			Messages: []message{{Text: "visible message", TS: "1234.0001"}},
		})
	})

	conn := newConn(t, Config{Token: "xoxb-test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1 (only from C_OK)", len(chunks))
	}
	if string(chunks[0].Data) != "visible message" {
		t.Errorf("data = %q, want 'visible message'", chunks[0].Data)
	}
}

// TestFileMetadata exercises files.info fallback when the file's
// url_private_download is empty in the message payload.
func TestFileMetadata(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(conversationsListResp{
			OK:       true,
			Channels: []channelInfo{{ID: "C1", Name: "general"}},
		})
	})
	mux.HandleFunc("/api/conversations.history", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(conversationsHistoryResp{
			OK: true,
			Messages: []message{
				{
					Text: "msg with file but no url",
					TS:   "1234.0001",
					Files: []struct {
						ID                 string `json:"id"`
						Name               string `json:"name"`
						URLPrivateDownload string `json:"url_private_download"`
					}{
						{ID: "F99", Name: ""},
					},
				},
			},
		})
	})
	mux.HandleFunc("/api/files.info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(filesInfoResp{
			OK: true,
			File: struct {
				ID                 string `json:"id"`
				Name               string `json:"name"`
				URLPrivateDownload string `json:"url_private_download"`
			}{
				ID: "F99", Name: "report.csv", URLPrivateDownload: srv.URL + "/files/F99",
			},
		})
	})
	mux.HandleFunc("/files/F99", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a,b,c"))
	})

	conn := newConn(t, Config{Token: "xoxb-test", APIBase: srv.URL})
	chunks := drainChunks(t, conn)

	// Expect 2 chunks: the message text + the file content.
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	var gotFile bool
	for _, ch := range chunks {
		if string(ch.Data) == "a,b,c" {
			gotFile = true
			md := ch.SourceMetadata.Slack
			if md == nil {
				t.Fatal("nil Slack metadata on file chunk")
			}
			if md.Permalink != "report.csv" {
				t.Errorf("file name = %q, want report.csv", md.Permalink)
			}
		}
	}
	if !gotFile {
		t.Error("file chunk not found in output")
	}
}

// TestVerify_OKAndNotOK covers the Verify state matrix: ok:true → verified,
// ok:false → not verified.
func TestVerify_OKAndNotOK(t *testing.T) {
	var okResp atomic.Bool
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/api/auth.test", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    okResp.Load(),
			"error": "not_authed",
		})
	})
	conn := &Connector{}
	conn.cfg.APIBase = srv.URL

	okResp.Store(true)
	verified, err := conn.Verify(context.Background(), "xoxb-real")
	if err != nil || !verified {
		t.Errorf("ok=true: want verified=true err=nil, got verified=%v err=%v", verified, err)
	}

	okResp.Store(false)
	verified, err = conn.Verify(context.Background(), "xoxb-bad")
	if err != nil || verified {
		t.Errorf("ok=false: want verified=false err=nil, got verified=%v err=%v", verified, err)
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
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cli := NewClient(srv.URL, "xoxb-test", nil)
	var sleeps []time.Duration
	cli.testSleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	var out struct{}
	if err := cli.GetJSON(context.Background(), "/test", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2 (one 429, one 200)", got)
	}
	if len(sleeps) != 1 {
		t.Errorf("expected exactly one backoff sleep, got %d", len(sleeps))
	}
}

// TestRegistry confirms init() side-effects: the slack connector is
// addressable via both the SaaS connector registry AND the source registry.
func TestRegistry(t *testing.T) {
	c := connectors.New("slack")
	if c == nil {
		t.Fatal("connectors.New(\"slack\") returned nil")
	}
	d := c.Descriptor()
	if d.Name != "slack" {
		t.Errorf("descriptor name = %q, want slack", d.Name)
	}
	if !d.Capabilities.Has(connectors.CapSource) || !d.Capabilities.Has(connectors.CapVerify) {
		t.Errorf("capabilities = %b, want CapSource | CapVerify", d.Capabilities)
	}
	if d.SourceType != sources.SourceSlack {
		t.Errorf("descriptor SourceType = %v, want SourceSlack", d.SourceType)
	}
	src := sources.New(sources.SourceSlack)
	if src == nil {
		t.Fatal("sources.New(SourceSlack) returned nil")
	}
	if src.Type() != sources.SourceSlack {
		t.Errorf("Type() = %v, want SourceSlack", src.Type())
	}
}

// TestSingleChannelMode verifies that when Config.Channel is set, the
// connector skips conversations.list and scans only that channel.
func TestSingleChannelMode(t *testing.T) {
	var listHits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		listHits.Add(1)
		t.Error("conversations.list should not be called in single-channel mode")
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/conversations.history", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("channel") != "C_TARGET" {
			t.Errorf("history channel = %q, want C_TARGET", r.URL.Query().Get("channel"))
		}
		_ = json.NewEncoder(w).Encode(conversationsHistoryResp{
			OK:       true,
			Messages: []message{{Text: "target message", TS: "1234.0001"}},
		})
	})

	conn := newConn(t, Config{Token: "xoxb-test", Channel: "C_TARGET", APIBase: srv.URL})
	chunks := drainChunks(t, conn)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if string(chunks[0].Data) != "target message" {
		t.Errorf("data = %q, want 'target message'", chunks[0].Data)
	}
	if listHits.Load() != 0 {
		t.Error("conversations.list should not have been called")
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

// drainChunks runs Chunks against conn and collects every emitted
// *Chunk. Uses a buffered channel + closer goroutine so a stalled
// producer cannot deadlock the test.
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
