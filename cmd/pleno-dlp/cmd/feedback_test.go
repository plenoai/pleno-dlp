package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/feedback"
)

func TestFeedbackSend(t *testing.T) {
	var got feedback.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	isolateTelemetry(t, map[string]string{crash.EnvEndpoint: srv.URL})

	out, err := runRoot(t, "feedback", "--yes", "hello", "world")
	if err != nil || got.Message != "hello world" || got.Schema != feedback.Schema || !strings.Contains(out, "feedback sent") {
		t.Fatalf("feedback: %v %+v\n%s", err, got, out)
	}
}

func TestFeedbackReadsStdin(t *testing.T) {
	var got feedback.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	isolateTelemetry(t, map[string]string{crash.EnvEndpoint: srv.URL})

	Root.SetIn(strings.NewReader("from stdin\n"))
	if _, err := runRoot(t, "feedback", "--yes"); err != nil || got.Message != "from stdin" {
		t.Fatalf("stdin feedback: %v %+v", err, got)
	}
}

func TestFeedbackRedactsMessage(t *testing.T) {
	var got feedback.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	isolateTelemetry(t, map[string]string{crash.EnvEndpoint: srv.URL})

	if _, err := runRoot(t, "feedback", "--yes", "mail me at bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Message, "bob@example.com") || !strings.Contains(got.Message, "[EMAIL]") {
		t.Fatalf("message not redacted: %q", got.Message)
	}
}

func TestFeedbackRequiresYesNonInteractive(t *testing.T) {
	isolateTelemetry(t, map[string]string{})
	Root.SetIn(strings.NewReader(""))
	_, err := runRoot(t, "feedback", "hi")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("err = %v", err)
	}
}

func TestFeedbackThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	isolateTelemetry(t, map[string]string{crash.EnvEndpoint: srv.URL})

	for i := 0; i < crash.FeedbackSendLimit; i++ {
		if _, err := runRoot(t, "feedback", "--yes", "msg"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	_, err := runRoot(t, "feedback", "--yes", "msg")
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("over-limit err = %v", err)
	}
}

func TestFeedbackEmptyMessage(t *testing.T) {
	isolateTelemetry(t, map[string]string{})
	Root.SetIn(strings.NewReader(""))
	if _, err := runRoot(t, "feedback", "--yes"); err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("err = %v", err)
	}
}
