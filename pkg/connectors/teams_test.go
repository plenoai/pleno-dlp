package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type fakeGraph struct {
	mu        sync.Mutex
	srv       *httptest.Server
	modified  string // lastModifiedDateTime of message m2
	foreign   string // when set, the messages page links to this origin
	failReply bool
}

func (f *fakeGraph) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer graph-token" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	base := f.srv.URL + "/v1.0"
	switch {
	case r.URL.Path == "/v1.0/me/joinedTeams":
		write(map[string]any{"value": []any{map[string]any{"id": "t1", "displayName": "Eng"}}})
	case r.URL.Path == "/v1.0/teams/t1/channels":
		write(map[string]any{"value": []any{map[string]any{"id": "c1", "displayName": "general"}}})
	case r.URL.Path == "/v1.0/teams/t1/channels/c1/messages" && r.URL.Query().Get("page") == "":
		next := base + "/teams/t1/channels/c1/messages?page=2"
		if f.foreign != "" {
			next = f.foreign + "/teams/t1/channels/c1/messages?page=2"
		}
		write(map[string]any{
			"value": []any{map[string]any{
				"id": "m1", "lastModifiedDateTime": "2026-01-01T00:00:00Z",
				"body": map[string]any{"content": "<p>hello</p>"}, "webUrl": "https://teams.example/m1",
			}},
			"@odata.nextLink": next,
		})
	case r.URL.Path == "/v1.0/teams/t1/channels/c1/messages":
		write(map[string]any{"value": []any{
			map[string]any{"id": "m2", "lastModifiedDateTime": f.modified, "subject": "deploy", "body": map[string]any{"content": "token=abc"}},
			map[string]any{"id": "m3", "deletedDateTime": "2026-01-02T00:00:00Z", "body": map[string]any{"content": "gone"}},
		}})
	case strings.HasSuffix(r.URL.Path, "/replies"):
		if f.failReply && strings.Contains(r.URL.Path, "/m2/") {
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			return
		}
		if strings.Contains(r.URL.Path, "/m1/") {
			write(map[string]any{"value": []any{map[string]any{"id": "r1", "replyToId": "m1", "lastModifiedDateTime": "2026-01-01T01:00:00Z", "body": map[string]any{"content": "reply secret"}}}})
			return
		}
		write(map[string]any{"value": []any{}})
	default:
		http.NotFound(w, r)
	}
}

func newFakeGraph(t *testing.T) *fakeGraph {
	f := &fakeGraph{modified: "2026-01-01T00:00:00Z"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(f.srv.Close)
	return f
}

func runTeams(t *testing.T, cfg Config) (map[string]string, error) {
	t.Helper()
	got := map[string]string{}
	err := scanTeams(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		if meta.SIEM == nil || meta.SIEM.Provider != "teams" || !strings.HasSuffix(meta.SIEM.Index, "/general") {
			return fmt.Errorf("bad meta %+v", meta.SIEM)
		}
		got[meta.SIEM.EventID] = string(data)
		return nil
	})
	return got, err
}

func TestTeamsScanMessagesRepliesAndIncremental(t *testing.T) {
	f := newFakeGraph(t)
	cfg := Config{"token": "graph-token", "base_url": f.srv.URL + "/v1.0"}
	got, err := runTeams(t, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, k := range []string{"t1/c1/m1", "t1/c1/m2", "t1/c1/m1/r1"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	if _, ok := got["t1/c1/m3"]; ok {
		t.Error("deleted message must not be emitted")
	}
	if !strings.Contains(got["t1/c1/m2"], "deploy") || !strings.Contains(got["t1/c1/m2"], "token=abc") {
		t.Errorf("m2 text = %q", got["t1/c1/m2"])
	}

	f.mu.Lock()
	f.modified = "2026-02-01T00:00:00Z"
	f.mu.Unlock()
	got, err = runTeams(t, Config{"token": "graph-token", "base_url": f.srv.URL + "/v1.0", configKeyIncrementalPreviousState: cfg[configKeyIncrementalNextState]})
	if err != nil {
		t.Fatalf("incremental scan: %v", err)
	}
	if len(got) != 1 || got["t1/c1/m2"] == "" {
		t.Fatalf("incremental scan emitted %v, want only edited m2", got)
	}
}

func TestTeamsRefusesForeignNextLink(t *testing.T) {
	f := newFakeGraph(t)
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer evil.Close()
	f.foreign = evil.URL
	_, err := runTeams(t, Config{"token": "graph-token", "base_url": f.srv.URL + "/v1.0"})
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || !strings.Contains(err.Error(), "foreign origin") {
		t.Fatalf("want degraded foreign-origin error, got %v", err)
	}
	if leaked {
		t.Fatal("token was sent to a foreign nextLink origin")
	}
}

func TestTeamsReplyFailureIsDegraded(t *testing.T) {
	f := newFakeGraph(t)
	f.failReply = true
	got, err := runTeams(t, Config{"token": "graph-token", "base_url": f.srv.URL + "/v1.0", "team_ids": "t1"})
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 {
		t.Fatalf("want 1 degraded failure, got %v", err)
	}
	if got["t1/c1/m1/r1"] == "" {
		t.Fatal("other replies should still be scanned")
	}
}

func TestTeamsEmitErrorAborts(t *testing.T) {
	f := newFakeGraph(t)
	sentinel := errors.New("sink closed")
	err := scanTeams(context.Background(), Config{"token": "graph-token", "base_url": f.srv.URL + "/v1.0"}, func([]byte, sources.Metadata) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("emit error must abort the scan, got %v", err)
	}
	var degraded *engine.DegradedError
	if errors.As(err, &degraded) {
		t.Fatal("emit error must not be reported as degraded coverage")
	}
}

func TestTeamsVerifyAndConfig(t *testing.T) {
	f := newFakeGraph(t)
	// /organization is not routed by the fake -> 404 for a good token surfaces as an error,
	// a bad token is 401 -> not verified.
	ok, err := verifyTeams(context.Background(), Config{"base_url": f.srv.URL + "/v1.0"}, "bad")
	if ok || err != nil {
		t.Fatalf("bad token: ok=%v err=%v", ok, err)
	}
	if _, err := newTeamsClient(Config{}); err == nil {
		t.Fatal("missing token should fail")
	}
	if _, err := newTeamsClient(Config{"token": "x", "base_url": "http://graph.example.com"}); err == nil {
		t.Fatal("plain http to non-loopback should fail")
	}
	if fp, err := fingerprintTeams(context.Background(), Config{"token": "one", "team_ids": "t1"}); err != nil || fp != "" {
		t.Fatalf("want empty fingerprint (per-message state drives incremental), got %q, %v", fp, err)
	}
}
