package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/feedback"
)

// isolateFeedback points the feedback command at a temp config dir and env.
func isolateFeedback(t *testing.T, env map[string]string) string {
	t.Helper()
	resetCommandFlags(t)
	dir := t.TempDir()
	env[crash.EnvDir] = dir
	prev := feedbackGetenv
	feedbackGetenv = func(k string) string { return env[k] }
	t.Cleanup(func() {
		feedbackGetenv = prev
		feedbackCmd.SetIn(os.Stdin)
	})
	return dir
}

// swapTTY makes the confirmation prompt read answer from f.
func swapTTY(t *testing.T, f *os.File) {
	t.Helper()
	prev := feedbackOpenTTY
	feedbackOpenTTY = func() (*os.File, error) { return f, nil }
	t.Cleanup(func() { feedbackOpenTTY = prev })
}

// ttyFile returns an open file whose contents are answer, positioned at 0.
func ttyFile(t *testing.T, answer string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(answer); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func feedbackRelay(t *testing.T) (*httptest.Server, func() []feedback.Report) {
	t.Helper()
	var mu sync.Mutex
	var bodies []feedback.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var rep feedback.Report
		_ = json.Unmarshal(b, &rep)
		mu.Lock()
		bodies = append(bodies, rep)
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []feedback.Report {
		mu.Lock()
		defer mu.Unlock()
		return append([]feedback.Report(nil), bodies...)
	}
}

func TestFeedbackSendsAndSpools(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})

	out, err := runRoot(t, "feedback", "--yes", "hello", "world")
	if err != nil || !strings.Contains(out, "sent feedback report") {
		t.Fatalf("feedback: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 1 || bodies[0].Message != "hello world" {
		t.Fatalf("relay got %+v", bodies)
	}
	sp, _, err := feedback.ReadReport(filepath.Join(dir, "feedback", feedback.LastFile))
	if err != nil || sp.Message != "hello world" || sp.Schema != feedback.Schema {
		t.Fatalf("spooled copy = %+v, %v", sp, err)
	}
}

func TestFeedbackStdinPromptsOnTTY(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	swapTTY(t, ttyFile(t, "y\n"))
	feedbackCmd.SetIn(strings.NewReader("piped feedback\n"))

	out, err := runRoot(t, "feedback", "--stdin")
	if err != nil || !strings.Contains(out, "sent feedback report") {
		t.Fatalf("feedback --stdin: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 1 || bodies[0].Message != "piped feedback" {
		t.Fatalf("relay got %+v", bodies)
	}
}

func TestFeedbackDeclinedKeepsSpool(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	swapTTY(t, ttyFile(t, "n\n"))

	out, err := runRoot(t, "feedback", "do not send this")
	if err != nil || !strings.Contains(out, "not sent") {
		t.Fatalf("decline: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 0 {
		t.Fatalf("declined feedback was sent: %+v", bodies)
	}
	if _, _, err := feedback.ReadReport(filepath.Join(dir, "feedback", feedback.LastFile)); err != nil {
		t.Fatalf("declined report not spooled: %v", err)
	}
}

func TestFeedbackStdinWithoutTTYRequiresYes(t *testing.T) {
	isolateFeedback(t, map[string]string{})
	prev := feedbackOpenTTY
	feedbackOpenTTY = func() (*os.File, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { feedbackOpenTTY = prev })
	feedbackCmd.SetIn(strings.NewReader("piped feedback\n"))

	if _, err := runRoot(t, "feedback", "--stdin"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected a --yes hint, got %v", err)
	}
}

func TestFeedbackRedactsSecrets(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})

	if _, err := runRoot(t, "feedback", "--yes", "mail alice@example.com from 10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	bodies := got()
	if len(bodies) != 1 {
		t.Fatalf("relay got %+v", bodies)
	}
	if strings.Contains(bodies[0].Message, "alice@") || strings.Contains(bodies[0].Message, "10.1.2.3") {
		t.Fatalf("PII left the machine: %q", bodies[0].Message)
	}
}
