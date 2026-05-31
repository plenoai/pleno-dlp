package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	err := scanSlackChannel(context.Background(), cli, slackChannelInfo{ID: "C1"}, 2, emit)
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
	err := scanSlackChannel(context.Background(), cli, slackChannelInfo{ID: "C1"}, 2,
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
