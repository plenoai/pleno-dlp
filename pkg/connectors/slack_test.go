package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// captureSlackWarn swaps the package slackWarn var for the duration of a
// test and returns a slice that accumulates formatted warnings.
func captureSlackWarn(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	prev := slackWarn
	slackWarn = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, format)
	}
	t.Cleanup(func() { slackWarn = prev })
	return &got
}

// TestScanSlackThreadWarnsOnReplyError asserts that a thread whose
// conversations.replies call returns ok:false (e.g. ratelimited / auth) is
// surfaced via slackWarn instead of being silently dropped, while the rest
// of the channel scan keeps emitting. Without the fix the warning slice is
// empty and the error is invisible.
func TestScanSlackThreadWarnsOnReplyError(t *testing.T) {
	warns := captureSlackWarn(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "conversations.history"):
			// One message that is a thread parent (thread_ts == ts).
			_, _ = w.Write([]byte(`{"ok":true,"has_more":false,"messages":[{"text":"parent","ts":"1.0","thread_ts":"1.0"}]}`))
		case strings.Contains(r.URL.Path, "conversations.replies"):
			// Reply lookup fails at the Slack layer (ok:false).
			_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	cli := newSlackClient(srv.URL, "xoxb-test")
	var emitted int32
	emit := func(_ []byte, _ sources.Metadata) error {
		atomic.AddInt32(&emitted, 1)
		return nil
	}

	err := scanSlackChannel(context.Background(), cli, slackChannelInfo{ID: "C1"}, 2, nil, emit)
	if err != nil {
		t.Fatalf("scanSlackChannel returned fatal error, want nil: %v", err)
	}
	if got := atomic.LoadInt32(&emitted); got != 1 {
		t.Fatalf("emitted = %d, want 1 (parent message)", got)
	}
	if len(*warns) == 0 {
		t.Fatalf("expected a slackWarn for the ok:false replies response, got none")
	}
	if !strings.Contains((*warns)[0], "not ok") {
		t.Fatalf("warning = %q, want it to mention the not-ok replies response", (*warns)[0])
	}
}

// TestSlackClientURLNoDoubleAPI is the regression test for the
// `https://slack.com/api/api/auth.test` doubling. Request paths already
// carry `/api/`, so the base must be the host root. The other tests here
// pass a bare httptest base and match paths with strings.Contains, which
// could not see the doubled prefix — this one asserts the exact URL for
// the real default base and for a base that (as historically documented)
// still ends in /api.
func TestSlackClientURLNoDoubleAPI(t *testing.T) {
	cases := []struct {
		name string
		base string
	}{
		{"default", ""},
		{"host root", "https://slack.com"},
		{"trailing slash", "https://slack.com/"},
		{"legacy /api suffix", "https://slack.com/api"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSlackClient(tc.base, "xoxb-test")
			got := c.url("/api/auth.test")
			const want = "https://slack.com/api/auth.test"
			if got != want {
				t.Fatalf("url(/api/auth.test) = %q, want %q", got, want)
			}
			if strings.Contains(got, "/api/api/") {
				t.Fatalf("doubled /api in %q", got)
			}
		})
	}
}

// TestSlackRequestsExactAuthTestPath drives a real request through the
// client and records the path the mock server actually receives, asserting
// it is exactly /api/auth.test (not /api/api/auth.test).
func TestSlackRequestsExactAuthTestPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// srv.URL+"/api" exercises the legacy-suffix normalization on a live
	// request path, not just the url() helper.
	cli := newSlackClient(srv.URL+"/api", "xoxb-test")
	resp, err := cli.do(context.Background(), http.MethodPost, "/api/auth.test", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if gotPath != "/api/auth.test" {
		t.Fatalf("server received path %q, want /api/auth.test", gotPath)
	}
}

// TestScanSlackThreadWarnsOnReplyTransportError covers the getJSON error
// branch (non-context transport/decode failure) of scanSlackThread.
func TestScanSlackThreadWarnsOnReplyTransportError(t *testing.T) {
	warns := captureSlackWarn(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "conversations.history"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"has_more":false,"messages":[{"text":"parent","ts":"1.0","thread_ts":"1.0"}]}`))
		case strings.Contains(r.URL.Path, "conversations.replies"):
			// 500 -> getJSON returns a non-nil, non-context error.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	cli := newSlackClient(srv.URL, "xoxb-test")
	err := scanSlackChannel(context.Background(), cli, slackChannelInfo{ID: "C1"}, 2, nil,
		func(_ []byte, _ sources.Metadata) error { return nil })
	if err != nil {
		t.Fatalf("scanSlackChannel returned fatal error, want nil: %v", err)
	}
	if len(*warns) == 0 {
		t.Fatalf("expected a slackWarn for the failed replies fetch, got none")
	}
	if !strings.Contains((*warns)[0], "fetch failed") {
		t.Fatalf("warning = %q, want it to mention the failed fetch", (*warns)[0])
	}
}

func TestScanSlackIncrementalEmitsOnlyChangedMessages(t *testing.T) {
	messages := `[
		{"text":"old","ts":"1.0"},
		{"text":"keep","ts":"2.0"}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "conversations.history"):
			_, _ = w.Write([]byte(`{"ok":true,"has_more":false,"messages":` + messages + `}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	cfg := Config{"token": "xoxb-test", "channel": "C1", "api_base": srv.URL}
	var first []string
	if err := scanSlack(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanSlack: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "keep,old"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	messages = `[
		{"text":"new","ts":"1.0"},
		{"text":"keep","ts":"2.0"}
	]`
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)
	var second []string
	if err := scanSlack(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanSlack: %v", err)
	}
	if got, want := strings.Join(second, ","), "new"; got != want {
		t.Fatalf("second emitted %q, want only changed message %q", got, want)
	}
}
