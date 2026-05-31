package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestScanNotionSearch500SurfacesError asserts that a 5xx on /search aborts
// the scan with an error rather than silently decoding the error body into a
// zero-result page and reporting a clean (false-clean) scan. Without the
// status check in postJSON, json.Decode of the error body yields an empty
// notionSearchResult, the loop breaks on has_more=false, and scanNotion
// returns nil with zero emits — a critical miss for a secret scanner.
func TestScanNotionSearch500SurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/search") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"object":"error","status":500,"message":"boom"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","results":[]}`))
	}))
	defer srv.Close()

	cfg := Config{"token": "secret_test", "api_base": srv.URL}
	var emitted int32
	emit := func(_ []byte, _ sources.Metadata) error {
		atomic.AddInt32(&emitted, 1)
		return nil
	}

	err := scanNotion(context.Background(), cfg, emit)
	if err == nil {
		t.Fatalf("scanNotion returned nil on a 500 /search response, want an error (false-clean scan)")
	}
	if !strings.Contains(err.Error(), "search") {
		t.Fatalf("error = %q, want it to mention the failing search call", err.Error())
	}
	if got := atomic.LoadInt32(&emitted); got != 0 {
		t.Fatalf("emitted = %d on a failed search, want 0", got)
	}
}

// TestEmitNotionPage500SurfacesError asserts that a 5xx on /pages/{id}
// surfaces as an error from emitNotionPage (which scanNotion's per-item loop
// logs-and-continues) rather than being decoded into an empty page that emits
// nothing. Without the status check the decode succeeds on the error body and
// the page silently contributes zero findings.
func TestEmitNotionPage500SurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pages/") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"object":"error","status":500,"message":"boom"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cli := newNotionClient(srv.URL, "secret_test")
	var emitted int32
	emit := func(_ []byte, _ sources.Metadata) error {
		atomic.AddInt32(&emitted, 1)
		return nil
	}

	err := emitNotionPage(context.Background(), cli, notionSearchItem{Object: "page", ID: "abc"}, emit)
	if err == nil {
		t.Fatalf("emitNotionPage returned nil on a 500 /pages/{id} response, want an error")
	}
	if !strings.Contains(err.Error(), "page") {
		t.Fatalf("error = %q, want it to mention the failing page fetch", err.Error())
	}
	if got := atomic.LoadInt32(&emitted); got != 0 {
		t.Fatalf("emitted = %d on a failed page fetch, want 0", got)
	}
}

// TestScanNotionPage500ContinuesPerPage asserts the per-page log-and-continue
// semantics survive: a 500 on one page's /pages/{id} does not abort the whole
// scan (scanNotion still returns nil), mirroring how jira/confluence tolerate
// per-item failures.
func TestScanNotionPage500ContinuesPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/search"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","results":[{"object":"page","id":"abc","url":"u"}],"has_more":false}`))
		case strings.HasPrefix(r.URL.Path, "/pages/"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"object":"error","status":500}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[]}`))
		}
	}))
	defer srv.Close()

	cfg := Config{"token": "secret_test", "api_base": srv.URL}
	err := scanNotion(context.Background(), cfg, func(_ []byte, _ sources.Metadata) error { return nil })
	if err != nil {
		t.Fatalf("scanNotion aborted on a single bad page, want nil (per-page continue): %v", err)
	}
}
